import asyncio
import threading
import time
from collections import deque


class EventBus:
    def __init__(self, history=300):
        self.history, self.subs, self.lock = deque(maxlen=history), set(), threading.Lock()

    def publish(self, event: dict):
        event = {"ts": time.time(), **event}
        with self.lock:
            self.history.append(event)
            subs = list(self.subs)
        for loop, q in subs:
            loop.call_soon_threadsafe(q.put_nowait, event)

    def subscribe(self):
        sub = (asyncio.get_running_loop(), asyncio.Queue())
        with self.lock:
            self.subs.add(sub)
        return sub

    def unsubscribe(self, sub):
        with self.lock:
            self.subs.discard(sub)


bus = EventBus()