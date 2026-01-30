#include "AsyncTcpResolver.hpp"
#include "Message.hpp"
#include "types.hpp"
#include "util.hpp"

#include <boost/asio.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <vector>


namespace net = boost::asio;
using net::ip::udp;
using net::awaitable;
using net::use_awaitable;

AsyncUdpResolver::AsyncUdpResolver() : cache{} {}

awaitable<void> listen() {
    
}