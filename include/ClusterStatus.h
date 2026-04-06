#pragma once

#include <string>
#include <vector>

namespace area {

struct EndpointStatus {
    std::string id;
    std::string model;
    int tier;
    int in_flight;
    int max_concurrent;
    bool healthy;
};

struct ClusterSnapshot {
    std::vector<EndpointStatus> endpoints;
};

class ClusterStatusProvider {
public:
    virtual ~ClusterStatusProvider() = default;
    virtual ClusterSnapshot snapshot() const = 0;
};

} // namespace area
