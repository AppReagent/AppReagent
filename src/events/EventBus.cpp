#include "events/EventBus.h"

namespace area {

void EventBus::subscribe(EventType type, Callback cb) {
    std::lock_guard lk(mu_);
    typed_.emplace_back(type, std::move(cb));
}

void EventBus::subscribe(Callback cb) {
    std::lock_guard lk(mu_);
    global_.push_back(std::move(cb));
}

void EventBus::emit(Event event) {
    std::lock_guard lk(mu_);
    for (auto& [type, cb] : typed_) {
        if (type == event.type) cb(event);
    }
    for (auto& cb : global_) {
        cb(event);
    }
}

} // namespace area
