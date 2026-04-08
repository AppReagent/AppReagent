#pragma once

#include <functional>
#include <string>
#include <vector>
#include <utility>

namespace area {

struct Guide {
    std::string name;
    std::string content;
};

struct Sensor {
    std::string name;
    std::string trigger;
    std::function<std::string(const std::string& action, const std::string& observation)> check;
};

class Harness {
 public:
    void addGuide(Guide g) { guides_.push_back(std::move(g)); }
    void addSensor(Sensor s) { sensors_.push_back(std::move(s)); }

    std::string guideText() const;

    std::string runSensors(const std::string& trigger,
                           const std::string& action,
                           const std::string& observation) const;

    static Harness createDefault();

    void loadConstitution(const std::string& path);

 private:
    std::vector<Guide> guides_;
    std::vector<Sensor> sensors_;
};

}  // namespace area
