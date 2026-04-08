#include "infra/events/EventBus.h"

#include <algorithm>

namespace area {

SubscriptionId EventBus::subscribe(EventType type, Callback cb) {
    std::lock_guard lk(mu_);
    auto id = nextId_++;
    typed_.push_back({id, type, std::move(cb)});
    return id;
}

SubscriptionId EventBus::subscribe(Callback cb) {
    std::lock_guard lk(mu_);
    auto id = nextId_++;
    global_.push_back({id, std::move(cb)});
    return id;
}

void EventBus::unsubscribe(SubscriptionId id) {
    std::lock_guard lk(mu_);
    typed_.erase(
        std::remove_if(typed_.begin(), typed_.end(),
                       [id](const TypedSub& s) { return s.id == id; }),
        typed_.end());
    global_.erase(
        std::remove_if(global_.begin(), global_.end(),
                       [id](const GlobalSub& s) { return s.id == id; }),
        global_.end());
}

void EventBus::emit(Event event) {
    std::vector<Callback> toCall;
    {
        std::lock_guard lk(mu_);
        for (auto& s : typed_) {
            if (s.type == event.type) toCall.push_back(s.cb);
        }
        for (auto& s : global_) {
            toCall.push_back(s.cb);
        }
    }
    for (auto& cb : toCall) {
        cb(event);
    }
}

}  // namespace area
