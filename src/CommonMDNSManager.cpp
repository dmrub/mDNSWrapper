/*
 * CommonMDNSManager.cpp
 *
 *  Created on: Jan 20, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"

#include <atomic>

namespace MDNS
{

namespace
{
static std::atomic<MDNSService::Id> currentId(1);
} // unnamed namespace

MDNSService::Id MDNSManager::getNewServiceId()
{
    return currentId++;
}

} // namespace MDNS
