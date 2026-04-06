#pragma once

#include <functional>
#include <string>
#include <vector>

namespace area {

// Feedforward control — steers agent behavior before action.
// Content is injected into the system prompt.
struct Guide {
    std::string name;
    std::string content;
};

// Feedback control — observes after action and enables self-correction.
// Returns empty string if OK, or a feedback message if issue detected.
struct Sensor {
    std::string name;
    std::string trigger; // "sql", "scan", "shell", "answer", "thought"
    std::function<std::string(const std::string& action, const std::string& observation)> check;
};

// Harness = Guides (feedforward) + Sensors (feedback)
// "Agent = Model + Harness" — Birgitta Böckeler
class Harness {
public:
    void addGuide(Guide g) { guides_.push_back(std::move(g)); }
    void addSensor(Sensor s) { sensors_.push_back(std::move(s)); }

    // Feedforward: all guide content concatenated for the system prompt
    std::string guideText() const;

    // Feedback: run all sensors matching a trigger, return combined feedback.
    // Empty string = all sensors passed.
    std::string runSensors(const std::string& trigger,
                           const std::string& action,
                           const std::string& observation) const;

    // Create harness with built-in guides and computational sensors
    static Harness createDefault();

    // Load a constitution file (SpecKit pattern) and add it as the first guide
    void loadConstitution(const std::string& path);

private:
    std::vector<Guide> guides_;
    std::vector<Sensor> sensors_;
};

} // namespace area
