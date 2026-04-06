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
    // Copy callbacks under lock, then invoke outside it to prevent deadlock
    // if a callback calls subscribe() or emit() on the same EventBus.
    std::vector<Callback> toCall;
    {
        std::lock_guard lk(mu_);
        for (auto& [type, cb] : typed_) {
            if (type == event.type) toCall.push_back(cb);
        }
        for (auto& cb : global_) {
            toCall.push_back(cb);
        }
    }
    for (auto& cb : toCall) {
        cb(event);
    }
}

} // namespace area
