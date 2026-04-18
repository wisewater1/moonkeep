import importlib
import os
import inspect
import asyncio
import time
from typing import Any, Optional
from abc import ABC, abstractmethod

class BasePlugin(ABC):
    event_queue: Optional[asyncio.Queue] = None
    target_store: Optional[Any] = None
    bettercap: Optional[Any] = None

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        ...

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def author(self) -> str:
        return "Moonkeep Core"

    @property
    def category(self) -> str:
        return "general"

    @abstractmethod
    async def start(self):
        pass

    @abstractmethod
    async def stop(self):
        pass

    def emit(self, event_type: str, data: Optional[dict] = None):
        """Emit a structured event to the global WebSocket bus."""
        if getattr(self, 'event_queue', None) and self.event_queue:
            payload = {
                "ts": time.time(),
                "plugin": getattr(self, 'name', "Unknown"),
                "type": event_type,
                "data": data or {}
            }
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(self.event_queue.put_nowait, payload)
            except RuntimeError:
                pass

    def log_event(self, msg: str, type: str = "INFO"):
        """Pipe operational logs to the global event system."""
        if hasattr(self, 'event_queue') and self.event_queue:
            payload = {"type": type, "msg": f"[{self.name}] {msg}"}
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(self.event_queue.put_nowait, payload)
            except RuntimeError:
                pass
        print(f"[{self.name}] {msg}")

class PluginManager:
    def __init__(self, plugins_dir: str):
        self.plugins_dir = plugins_dir
        self.plugins = {}

    def load_plugins(self):
        print(f"Loading plugins from {self.plugins_dir}...")
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = filename[:-3]
                module_path = f"plugins.{module_name}"
                try:
                    module = importlib.import_module(module_path)
                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj) and obj.__name__ != "BasePlugin":
                            # Resilient check for BasePlugin in MRO by name to avoid identity mismatches
                            if any(base.__name__ == "BasePlugin" for base in obj.__mro__):
                                try:
                                    plugin_instance = obj()
                                    self.plugins[plugin_instance.name] = plugin_instance
                                    print(f"Registered plugin: {plugin_instance.name} (from {module_name})")
                                except Exception as e:
                                    print(f"Error instantiating {name} in {module_name}: {e}")
                except Exception as e:
                    print(f"Failed to load module {module_name}: {e}")

    def get_plugin(self, name: str):
        return self.plugins.get(name)

    def list_plugins(self):
        return [
            {
                "name": p.name,
                "description": p.description,
                "version": p.version,
                "author": p.author,
                "category": p.category,
            }
            for p in self.plugins.values()
        ]
