#include "Resolver.hpp"
#include <iostream>
#include <netinet/in.h>

int main() {
    Resolver r;
    r.init();
    std::cout << "Server initialized" << std::endl;
    std::cout << "Listening..." << std::endl;
    r.listen();
}