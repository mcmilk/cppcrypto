/*
This code is written by kerukuro and released into public domain.
*/

#ifndef DIGESTPPMOD_MIXINS_NULL_HPP
#define DIGESTPPMOD_MIXINS_NULL_HPP

namespace digestppmod
{
namespace mixin
{

/**
 * \brief Empty mixin that does not have any additional fuctions.
 * \sa hasher
 */
template<typename T>
struct null_mixin
{
};

} // namespace mixin
} // namespace digestppmod

#endif // DIGESTPPMOD_MIXINS_NULL_HPP