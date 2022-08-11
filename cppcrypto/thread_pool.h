/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_THREADPOOL_H
#define CPPCRYPTO_THREADPOOL_H

#include "portability.h"
#ifndef NO_CPP11_THREADS
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#endif
#include <functional>
#include <vector>
#include <deque>
#include <memory>

namespace cppcrypto
{
	namespace detail
	{

class thread_pool;

#ifndef NO_CPP11_THREADS
class thread_worker
{
public:
	thread_worker(thread_pool* pool);

	~thread_worker();

	void run_async(std::function<void()>&& f);

private:
	void run();

	std::function<void()> func;
	thread_pool* pool;
	std::atomic<bool> added_flag;
	std::atomic<bool> shutdown_flag;
	std::condition_variable condition;
	std::mutex worker_mutex;
	std::thread worker_thread;
};
#endif

class thread_pool
{
public:
	thread_pool(size_t parallelism);
	void wait_for_all();
#ifndef NO_CPP11_THREADS
	void run_async(std::function<void()>&& f);
	bool get_work(std::function<void()>& f, thread_worker* thread_worker);

private:
	std::mutex pool_mutex;
	std::vector<std::shared_ptr<thread_worker>> threads;
	std::deque<thread_worker*> available_threads;
	std::deque<std::function<void()>> scheduled_tasks;
	bool threaded;
#endif
};


	}
}

#endif

