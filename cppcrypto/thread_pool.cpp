/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#include "thread_pool.h"
#include <algorithm>

using namespace std;

namespace cppcrypto
{
	namespace detail
	{
		thread_pool::thread_pool(size_t parallelism)
		{
#ifndef NO_CPP11_THREADS
			threaded = parallelism > 0;
			if (threaded)
			{
				unsigned int nthreads = std::min(static_cast<unsigned int>(parallelism), thread::hardware_concurrency());
				for (unsigned int i = 0; i < nthreads; i++)
				{
					shared_ptr<thread_worker> thread_worker_ptr(new thread_worker(this));
					threads.push_back(thread_worker_ptr);
					available_threads.push_back(thread_worker_ptr.get());
				}
			}
#endif
		}

		void thread_pool::wait_for_all()
		{
#ifndef NO_CPP11_THREADS
			for (;;)
			{
				unique_lock<mutex> lock(pool_mutex);
				if (available_threads.size() == threads.size())
					return;
				lock.unlock();
				std::this_thread::yield();
			}
#endif
		}

#ifndef NO_CPP11_THREADS
		bool thread_pool::get_work(std::function<void()>& f, thread_worker* thread_worker)
		{
			unique_lock<mutex> lock(pool_mutex);
			if (!scheduled_tasks.empty())
			{
				f = scheduled_tasks.front();
				scheduled_tasks.pop_front();
				return true;
			}
			available_threads.push_back(thread_worker);
			return false;
		}

		void thread_pool::run_async(function<void()>&& f)
		{
			if (!threaded)
				return f();

			unique_lock<mutex> lock(pool_mutex);
			if (available_threads.empty())
			{
				scheduled_tasks.push_back(f);
				return;
			}

			thread_worker* freethread_worker = available_threads.back();
			available_threads.pop_back();
			freethread_worker->run_async(std::forward<function<void()>>(f));
		}

		thread_worker::thread_worker(thread_pool* pool) 
			: pool(pool), added_flag(false), shutdown_flag(false), worker_thread(bind(&thread_worker::run, this))
		{
		}

		thread_worker::~thread_worker()
		{
			shutdown_flag.store(true);
			condition.notify_all();
			worker_thread.join();
		}

		void thread_worker::run_async(function<void()>&& f)
		{
			unique_lock<mutex> lock(worker_mutex);
			func = std::move(f);
			added_flag.store(true);
			condition.notify_one();
		}

		void thread_worker::run()
		{
			while (!shutdown_flag)
			{
				unique_lock<mutex> lock(worker_mutex);
				condition.wait(lock, [this] { return added_flag.load() || shutdown_flag.load(); });
				bool was_added = added_flag;
				added_flag.store(false);
				lock.unlock();
				while (was_added)
				{
					func();
					was_added = pool->get_work(func, this);
				}
			}
		}
#endif
	}
}

