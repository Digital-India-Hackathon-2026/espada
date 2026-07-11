# runtime/core/events.py
"""
Internal Event Bus System

This module provides a comprehensive event-driven architecture for the runtime,
supporting synchronous and asynchronous event handling with priority queuing,
delayed execution, and sticky events.
"""

import asyncio
import uuid
import time
import logging
from typing import Any, Callable, Dict, List, Optional, Set, Union, Type, TypeVar, Awaitable
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from functools import wraps
import inspect

from pydantic import BaseModel, Field, ConfigDict

# Type variables for callbacks
T = TypeVar('T')
AsyncCallback = Callable[..., Awaitable[None]]
SyncCallback = Callable[..., None]
Callback = Union[SyncCallback, AsyncCallback]


class EventSeverity(str, Enum):
    """Event severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    DEBUG = "debug"


class EventCategory(str, Enum):
    """Event categories for routing and filtering"""
    SYSTEM = "system"
    REQUEST = "request"
    SECURITY = "security"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    THREAT = "threat"
    POLICY = "policy"
    PLUGIN = "plugin"
    METRICS = "metrics"
    HEALTH = "health"
    ERROR = "error"
    CUSTOM = "custom"


class EventStatus(str, Enum):
    """Event processing status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EventPriority(int, Enum):
    """Event priority levels"""
    CRITICAL = 100
    HIGH = 75
    NORMAL = 50
    LOW = 25
    BACKGROUND = 10


class Event(BaseModel):
    """Base event class with standard metadata"""
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str
    severity: EventSeverity = EventSeverity.INFO
    category: EventCategory = EventCategory.CUSTOM
    priority: EventPriority = EventPriority.NORMAL
    timestamp: float = Field(default_factory=time.time)
    datetime: datetime = Field(default_factory=datetime.utcnow)
    source: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)
    status: EventStatus = EventStatus.PENDING
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    version: str = "1.0"
    
    model_config = ConfigDict(
        extra="allow",
        json_encoders={
            datetime: lambda dt: dt.isoformat(),
        }
    )
    
    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Convert to dictionary with proper datetime serialization"""
        result = super().dict(*args, **kwargs)
        result['datetime'] = self.datetime.isoformat()
        return result


class DelayedEvent(Event):
    """Event with delayed execution"""
    
    scheduled_time: Optional[float] = None
    delay_seconds: float = 0.0
    retry_count: int = 0
    max_retries: int = 3
    retry_delay: float = 1.0


class StickyEvent(Event):
    """Event that persists for new subscribers"""
    
    sticky_until: Optional[float] = None
    sticky_duration: float = 300.0  # 5 minutes default


# Concrete Event Types
class RuntimeStarted(Event):
    def __init__(self, **kwargs):
        super().__init__(type="runtime.started", category=EventCategory.SYSTEM, severity=EventSeverity.INFO, **kwargs)


class RuntimeStopped(Event):
    def __init__(self, **kwargs):
        super().__init__(type="runtime.stopped", category=EventCategory.SYSTEM, severity=EventSeverity.INFO, **kwargs)


class RuntimePaused(Event):
    def __init__(self, **kwargs):
        super().__init__(type="runtime.paused", category=EventCategory.SYSTEM, severity=EventSeverity.INFO, **kwargs)


class RuntimeResumed(Event):
    def __init__(self, **kwargs):
        super().__init__(type="runtime.resumed", category=EventCategory.SYSTEM, severity=EventSeverity.INFO, **kwargs)


class RuntimeReloaded(Event):
    def __init__(self, **kwargs):
        super().__init__(type="runtime.reloaded", category=EventCategory.SYSTEM, severity=EventSeverity.INFO, **kwargs)


class RequestReceived(Event):
    def __init__(self, **kwargs):
        super().__init__(type="request.received", category=EventCategory.REQUEST, severity=EventSeverity.INFO, **kwargs)


class RequestCompleted(Event):
    def __init__(self, **kwargs):
        super().__init__(type="request.completed", category=EventCategory.REQUEST, severity=EventSeverity.INFO, **kwargs)


class ThreatDetected(Event):
    def __init__(self, **kwargs):
        super().__init__(type="threat.detected", category=EventCategory.THREAT, severity=EventSeverity.HIGH, **kwargs)


class SecretDetected(Event):
    def __init__(self, **kwargs):
        super().__init__(type="secret.detected", category=EventCategory.THREAT, severity=EventSeverity.HIGH, **kwargs)


class PromptInjectionDetected(Event):
    def __init__(self, **kwargs):
        super().__init__(type="prompt.injection.detected", category=EventCategory.THREAT, severity=EventSeverity.HIGH, **kwargs)


class PolicyViolation(Event):
    def __init__(self, **kwargs):
        super().__init__(type="policy.violation", category=EventCategory.POLICY, severity=EventSeverity.HIGH, **kwargs)


class AuthenticationSuccess(Event):
    def __init__(self, **kwargs):
        super().__init__(type="authentication.success", category=EventCategory.AUTHENTICATION, severity=EventSeverity.INFO, **kwargs)


class AuthenticationFailure(Event):
    def __init__(self, **kwargs):
        super().__init__(type="authentication.failure", category=EventCategory.AUTHENTICATION, severity=EventSeverity.HIGH, **kwargs)


class AuthorizationFailure(Event):
    def __init__(self, **kwargs):
        super().__init__(type="authorization.failure", category=EventCategory.AUTHORIZATION, severity=EventSeverity.HIGH, **kwargs)


class RequestBlocked(Event):
    def __init__(self, **kwargs):
        super().__init__(type="request.blocked", category=EventCategory.SECURITY, severity=EventSeverity.HIGH, **kwargs)


class RequestAllowed(Event):
    def __init__(self, **kwargs):
        super().__init__(type="request.allowed", category=EventCategory.SECURITY, severity=EventSeverity.INFO, **kwargs)


class PluginLoaded(Event):
    def __init__(self, **kwargs):
        super().__init__(type="plugin.loaded", category=EventCategory.PLUGIN, severity=EventSeverity.INFO, **kwargs)


class PluginUnloaded(Event):
    def __init__(self, **kwargs):
        super().__init__(type="plugin.unloaded", category=EventCategory.PLUGIN, severity=EventSeverity.INFO, **kwargs)


class MetricsUpdated(Event):
    def __init__(self, **kwargs):
        super().__init__(type="metrics.updated", category=EventCategory.METRICS, severity=EventSeverity.DEBUG, **kwargs)


class HealthChanged(Event):
    def __init__(self, **kwargs):
        super().__init__(type="health.changed", category=EventCategory.HEALTH, severity=EventSeverity.INFO, **kwargs)


class ErrorOccurred(Event):
    def __init__(self, **kwargs):
        super().__init__(type="error.occurred", category=EventCategory.ERROR, severity=EventSeverity.HIGH, **kwargs)


class Subscription:
    """Event subscription wrapper"""
    
    def __init__(
        self,
        event_type: str,
        callback: Callback,
        priority: int = 50,
        filter_func: Optional[Callable[[Event], bool]] = None,
        once: bool = False,
        id: Optional[str] = None,
    ):
        self.id = id or str(uuid.uuid4())
        self.event_type = event_type
        self.callback = callback
        self.priority = priority
        self.filter_func = filter_func
        self.once = once
        self.is_async = asyncio.iscoroutinefunction(callback)
        self.created_at = time.time()
        self.last_triggered: Optional[float] = None
        self.trigger_count: int = 0
        self.is_active: bool = True
    
    def should_process(self, event: Event) -> bool:
        """Check if this subscription should process the event"""
        if not self.is_active:
            return False
        if self.filter_func and not self.filter_func(event):
            return False
        if self.once and self.trigger_count > 0:
            return False
        return True
    
    async def execute(self, event: Event) -> Any:
        """Execute the callback with the event"""
        try:
            self.last_triggered = time.time()
            self.trigger_count += 1
            
            if self.is_async:
                return await self.callback(event)
            else:
                # Run sync callbacks in thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, self.callback, event)
        except Exception as e:
            logging.getLogger(__name__).error(
                f"Error executing event callback: {e}",
                extra={"event_id": event.id, "subscription_id": self.id}
            )
            raise
    
    def __repr__(self) -> str:
        return f"<Subscription id={self.id} type={self.event_type} priority={self.priority} once={self.once}>"


class EventBus:
    """
    Internal Event Bus implementation
    
    Handles event publishing, subscribing, and processing with support for:
    - Synchronous and asynchronous event handlers
    - Priority-based event ordering
    - Delayed events
    - Sticky events for late subscribers
    - Event filtering
    - Once-only subscriptions
    - Wildcard event types (*)
    - Event correlation
    """
    
    def __init__(self, name: str = "default", max_queue_size: int = 10000):
        """
        Initialize the event bus
        
        Args:
            name: Event bus name for identification
            max_queue_size: Maximum events in queue before blocking
        """
        self.name = name
        self._subscriptions: Dict[str, List[Subscription]] = {}
        self._sticky_events: Dict[str, StickyEvent] = {}
        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self._is_running: bool = False
        self._workers: List[asyncio.Task] = []
        self._worker_count: int = 4
        self._logger = logging.getLogger(f"{__name__}.{name}")
        self._metrics: Dict[str, int] = {
            "published": 0,
            "processed": 0,
            "failed": 0,
            "filtered": 0,
        }
        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()
    
    def subscribe(
        self,
        event_type: str,
        callback: Callback,
        priority: int = EventPriority.NORMAL,
        filter_func: Optional[Callable[[Event], bool]] = None,
        once: bool = False,
    ) -> str:
        """
        Subscribe to an event type
        
        Args:
            event_type: Event type to subscribe to (use '*' for all events)
            callback: Callback function to execute
            priority: Priority of the subscription (higher = first)
            filter_func: Optional filter function
            once: If True, subscription is removed after first execution
            
        Returns:
            str: Subscription ID for unsubscribing
        """
        subscription = Subscription(
            event_type=event_type,
            callback=callback,
            priority=priority,
            filter_func=filter_func,
            once=once,
        )
        
        if event_type not in self._subscriptions:
            self._subscriptions[event_type] = []
        
        # Insert in priority order
        subs = self._subscriptions[event_type]
        insert_pos = 0
        for i, s in enumerate(subs):
            if s.priority < priority:
                insert_pos = i
                break
            insert_pos = i + 1
        
        subs.insert(insert_pos, subscription)
        
        self._logger.debug(f"Subscribed to {event_type} (id: {subscription.id})")
        
        # Check if there are any sticky events for this type
        if event_type in self._sticky_events:
            asyncio.create_task(self._deliver_sticky_event(event_type, subscription))
        
        return subscription.id
    
    def unsubscribe(self, subscription_id: str) -> bool:
        """
        Unsubscribe a subscription by ID
        
        Args:
            subscription_id: Subscription ID to remove
            
        Returns:
            bool: True if removed, False if not found
        """
        for event_type, subscriptions in self._subscriptions.items():
            for i, sub in enumerate(subscriptions):
                if sub.id == subscription_id:
                    subscriptions.pop(i)
                    if not subscriptions:
                        del self._subscriptions[event_type]
                    self._logger.debug(f"Unsubscribed {subscription_id}")
                    return True
        return False
    
    def unsubscribe_all(self, event_type: str) -> int:
        """
        Unsubscribe all subscriptions for an event type
        
        Args:
            event_type: Event type to clear
            
        Returns:
            int: Number of subscriptions removed
        """
        if event_type not in self._subscriptions:
            return 0
        
        count = len(self._subscriptions[event_type])
        del self._subscriptions[event_type]
        self._logger.debug(f"Unsubscribed all from {event_type} ({count} subscriptions)")
        return count
    
    def register(self, event_class: Type[Event]) -> None:
        """
        Register an event class for automatic handling
        
        Args:
            event_class: Event class to register
        """
        # This is a no-op for now - keeping for compatibility
        # In future, could add schema validation or event registration
        self._logger.debug(f"Registered event class: {event_class.__name__}")
    
    async def publish(self, event: Union[Event, DelayedEvent, StickyEvent]) -> str:
        """
        Publish an event to the event bus
        
        Args:
            event: Event to publish
            
        Returns:
            str: Event ID
        """
        if isinstance(event, DelayedEvent) and event.delay_seconds > 0:
            # Schedule delayed event
            asyncio.create_task(self._publish_delayed(event))
            self._logger.debug(f"Scheduled delayed event {event.id} ({event.delay_seconds}s)")
            return event.id
        
        # Add event to queue
        await self._event_queue.put(event)
        self._metrics["published"] += 1
        
        # Handle sticky events
        if isinstance(event, StickyEvent):
            self._sticky_events[event.type] = event
            self._logger.debug(f"Sticky event stored: {event.type}")
        
        self._logger.debug(f"Published event {event.id} of type {event.type}")
        return event.id
    
    async def _publish_delayed(self, event: DelayedEvent) -> None:
        """Handle delayed event publishing"""
        await asyncio.sleep(event.delay_seconds)
        
        event.scheduled_time = time.time()
        await self.publish(event)
    
    async def emit(self, event_type: str, payload: Dict[str, Any] = None, **kwargs) -> Event:
        """
        Create and publish an event in one call
        
        Args:
            event_type: Type of event
            payload: Event payload
            **kwargs: Additional event fields
            
        Returns:
            Event: Created event
        """
        event = Event(
            type=event_type,
            payload=payload or {},
            **kwargs
        )
        await self.publish(event)
        return event
    
    def listen(
        self,
        event_type: str,
        priority: int = EventPriority.NORMAL,
        filter_func: Optional[Callable[[Event], bool]] = None,
        once: bool = False,
    ):
        """
        Decorator for listening to events
        
        Args:
            event_type: Event type to listen for
            priority: Subscription priority
            filter_func: Optional filter function
            once: If True, only receive once
            
        Returns:
            Decorator function
        """
        def decorator(func: Callback) -> Callback:
            self.subscribe(event_type, func, priority, filter_func, once)
            return func
        return decorator
    
    async def start(self, worker_count: int = 4) -> None:
        """
        Start the event bus processing
        
        Args:
            worker_count: Number of worker coroutines
        """
        if self._is_running:
            return
        
        self._is_running = True
        self._worker_count = worker_count
        self._shutdown_event.clear()
        
        # Start worker tasks
        for i in range(worker_count):
            worker = asyncio.create_task(self._worker_loop(i))
            self._workers.append(worker)
        
        self._logger.info(f"Event bus started with {worker_count} workers")
    
    async def stop(self, timeout: float = 10.0) -> None:
        """
        Stop the event bus gracefully
        
        Args:
            timeout: Maximum time to wait for workers
        """
        if not self._is_running:
            return
        
        self._is_running = False
        self._shutdown_event.set()
        
        # Wait for workers to finish
        if self._workers:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._workers, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                self._logger.warning(f"Event bus stop timed out after {timeout}s")
                # Cancel remaining workers
                for worker in self._workers:
                    worker.cancel()
            
            self._workers.clear()
        
        self._logger.info("Event bus stopped")
    
    async def _worker_loop(self, worker_id: int) -> None:
        """Worker coroutine for processing events"""
        self._logger.debug(f"Worker {worker_id} started")
        
        while self._is_running or not self._event_queue.empty():
            try:
                # Get event with timeout
                try:
                    event = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=0.5
                    )
                except asyncio.TimeoutError:
                    continue
                
                await self._process_event(event)
                self._event_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.error(f"Worker {worker_id} error: {e}")
                self._metrics["failed"] += 1
        
        self._logger.debug(f"Worker {worker_id} stopped")
    
    async def _process_event(self, event: Event) -> None:
        """Process a single event"""
        event.status = EventStatus.PROCESSING
        processed = 0
        
        try:
            # Get all matching subscriptions
            subscriptions = []
            
            # Direct match
            if event.type in self._subscriptions:
                subscriptions.extend(self._subscriptions[event.type])
            
            # Wildcard match
            if "*" in self._subscriptions:
                subscriptions.extend(self._subscriptions["*"])
            
            # Filter valid subscriptions
            valid_subscriptions = [s for s in subscriptions if s.should_process(event)]
            
            # Sort by priority (already sorted, but keep for safety)
            valid_subscriptions.sort(key=lambda s: -s.priority)
            
            # Execute subscriptions
            for sub in valid_subscriptions:
                try:
                    await sub.execute(event)
                    processed += 1
                    
                    # Remove once subscriptions
                    if sub.once:
                        self.unsubscribe(sub.id)
                        
                except Exception as e:
                    self._logger.error(
                        f"Error in subscription {sub.id}: {e}",
                        extra={"event_id": event.id}
                    )
                    self._metrics["failed"] += 1
            
            event.status = EventStatus.COMPLETED
            self._metrics["processed"] += 1
            
            self._logger.debug(
                f"Processed event {event.id} of type {event.type} "
                f"({processed} handlers executed)"
            )
            
        except Exception as e:
            event.status = EventStatus.FAILED
            self._logger.error(f"Failed to process event {event.id}: {e}")
            self._metrics["failed"] += 1
    
    async def _deliver_sticky_event(self, event_type: str, subscription: Subscription) -> None:
        """Deliver sticky event to new subscription"""
        async with self._lock:
            if event_type in self._sticky_events:
                event = self._sticky_events[event_type]
                
                # Check if sticky event is still valid
                if event.sticky_until and time.time() > event.sticky_until:
                    del self._sticky_events[event_type]
                    return
                
                try:
                    await subscription.execute(event)
                    self._logger.debug(f"Delivered sticky event {event.id} to {subscription.id}")
                except Exception as e:
                    self._logger.error(f"Failed to deliver sticky event: {e}")
    
    async def broadcast(self, events: List[Event]) -> List[str]:
        """
        Broadcast multiple events
        
        Args:
            events: List of events to publish
            
        Returns:
            List[str]: Event IDs
        """
        ids = []
        for event in events:
            event_id = await self.publish(event)
            ids.append(event_id)
        return ids
    
    def clear(self) -> None:
        """
        Clear all subscriptions and sticky events
        """
        self._subscriptions.clear()
        self._sticky_events.clear()
        
        # Clear queue if running
        if not self._event_queue.empty():
            while not self._event_queue.empty():
                try:
                    self._event_queue.get_nowait()
                    self._event_queue.task_done()
                except asyncio.QueueEmpty:
                    break
        
        self._logger.info("Event bus cleared")
    
    def remove(self, event_id: str) -> bool:
        """
        Remove an event from the queue (if pending)
        
        Args:
            event_id: Event ID to remove
            
        Returns:
            bool: True if removed
        """
        # Check in queue
        removed = False
        temp_queue = []
        
        while not self._event_queue.empty():
            try:
                event = self._event_queue.get_nowait()
                if event.id == event_id:
                    removed = True
                    self._event_queue.task_done()
                else:
                    temp_queue.append(event)
            except asyncio.QueueEmpty:
                break
        
        # Put back remaining events
        for event in temp_queue:
            self._event_queue.put_nowait(event)
        
        # Remove from sticky events if present
        for type_key in list(self._sticky_events.keys()):
            if self._sticky_events[type_key].id == event_id:
                del self._sticky_events[type_key]
                removed = True
        
        if removed:
            self._logger.debug(f"Removed event {event_id}")
        
        return removed
    
    def get_subscriptions(self, event_type: Optional[str] = None) -> Dict[str, List[Subscription]]:
        """
        Get all subscriptions
        
        Args:
            event_type: Optional event type filter
            
        Returns:
            Dict[str, List[Subscription]]: Subscriptions by type
        """
        if event_type:
            return {event_type: self._subscriptions.get(event_type, [])}
        return self._subscriptions.copy()
    
    def get_metrics(self) -> Dict[str, int]:
        """
        Get event bus metrics
        
        Returns:
            Dict[str, int]: Metrics dictionary
        """
        return {
            **self._metrics,
            "active_subscriptions": sum(len(subs) for subs in self._subscriptions.values()),
            "sticky_events": len(self._sticky_events),
            "queue_size": self._event_queue.qsize(),
            "workers": len(self._workers),
        }
    
    def get_sticky_events(self) -> Dict[str, StickyEvent]:
        """Get all sticky events"""
        return self._sticky_events.copy()
    
    def clear_sticky_events(self) -> None:
        """Clear all sticky events"""
        self._sticky_events.clear()
        self._logger.debug("Cleared all sticky events")
    
    def add_context_provider(self, provider: Callable[[], Dict[str, Any]]) -> None:
        """
        Add a context provider function that adds context to every event
        
        Args:
            provider: Function that returns context dictionary
        """
        # Store provider for use when publishing events
        if not hasattr(self, '_context_providers'):
            self._context_providers = []
        self._context_providers.append(provider)
    
    async def publish_with_context(
        self,
        event: Event,
        include_std_context: bool = True
    ) -> str:
        """
        Publish an event with additional context from providers
        
        Args:
            event: Event to publish
            include_std_context: Include standard context (timestamp, etc.)
            
        Returns:
            str: Event ID
        """
        if include_std_context:
            event.context.update({
                "event_bus": self.name,
                "published_at": datetime.utcnow().isoformat(),
            })
        
        if hasattr(self, '_context_providers'):
            for provider in self._context_providers:
                try:
                    context = provider()
                    if context:
                        event.context.update(context)
                except Exception as e:
                    self._logger.error(f"Error in context provider: {e}")
        
        return await self.publish(event)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()
    
    def __repr__(self) -> str:
        return f"<EventBus name={self.name} running={self._is_running} workers={len(self._workers)}>"


# Global default event bus instance
_default_bus: Optional[EventBus] = None


def get_event_bus(name: str = "default", **kwargs) -> EventBus:
    """
    Get or create an event bus instance
    
    Args:
        name: Event bus name
        **kwargs: Additional arguments for EventBus
        
    Returns:
        EventBus: Event bus instance
    """
    global _default_bus
    
    if name == "default":
        if _default_bus is None:
            _default_bus = EventBus(name=name, **kwargs)
        return _default_bus
    else:
        return EventBus(name=name, **kwargs)


def set_default_bus(bus: EventBus) -> None:
    """
    Set the default event bus instance
    
    Args:
        bus: EventBus instance
    """
    global _default_bus
    _default_bus = bus


# Convenience functions using default bus
async def publish(event: Event) -> str:
    """Publish event using default bus"""
    return await get_event_bus().publish(event)


def subscribe(event_type: str, callback: Callback, **kwargs) -> str:
    """Subscribe using default bus"""
    return get_event_bus().subscribe(event_type, callback, **kwargs)


def unsubscribe(subscription_id: str) -> bool:
    """Unsubscribe using default bus"""
    return get_event_bus().unsubscribe(subscription_id)


def listen(event_type: str, **kwargs):
    """Listen decorator using default bus"""
    return get_event_bus().listen(event_type, **kwargs)


# Event type registry for easy lookup
EVENT_TYPES = {
    "runtime.started": RuntimeStarted,
    "runtime.stopped": RuntimeStopped,
    "runtime.paused": RuntimePaused,
    "runtime.resumed": RuntimeResumed,
    "runtime.reloaded": RuntimeReloaded,
    "request.received": RequestReceived,
    "request.completed": RequestCompleted,
    "threat.detected": ThreatDetected,
    "secret.detected": SecretDetected,
    "prompt.injection.detected": PromptInjectionDetected,
    "policy.violation": PolicyViolation,
    "authentication.success": AuthenticationSuccess,
    "authentication.failure": AuthenticationFailure,
    "authorization.failure": AuthorizationFailure,
    "request.blocked": RequestBlocked,
    "request.allowed": RequestAllowed,
    "plugin.loaded": PluginLoaded,
    "plugin.unloaded": PluginUnloaded,
    "metrics.updated": MetricsUpdated,
    "health.changed": HealthChanged,
    "error.occurred": ErrorOccurred,
}


def create_event(event_type: str, **kwargs) -> Event:
    """
    Create an event by type name
    
    Args:
        event_type: Event type string
        **kwargs: Event attributes
        
    Returns:
        Event: Created event
    """
    event_class = EVENT_TYPES.get(event_type, Event)
    
    # If using generic Event, ensure type is set
    if event_class == Event:
        kwargs['type'] = event_type
    
    return event_class(**kwargs)


async def emit_event(event_type: str, payload: Dict[str, Any] = None, **kwargs) -> Event:
    """
    Create and emit an event using default bus
    
    Args:
        event_type: Event type
        payload: Event payload
        **kwargs: Additional event fields
        
    Returns:
        Event: Created event
    """
    event = create_event(event_type, payload=payload or {}, **kwargs)
    await publish(event)
    return event