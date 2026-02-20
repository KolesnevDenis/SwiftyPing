# SwiftyPing

Modern ICMP ping client for Swift.

SwiftyPing provides low-level ICMP echo requests with a simple API and supports both callback-based and async/await-based usage.

## Requirements

- iOS 15.0+
- macOS 12.0+
- Swift 5.10+
- Swift Package Manager

## Installation

### Swift Package Manager

```swift
.package(url: "https://github.com/KolesnevDenis/SwiftyPing", from: "2.0.0")
```

Then add `SwiftyPing` to your target dependencies.

## Quick Start

### Continuous ping (callbacks)

```swift
import SwiftyPing

let config = PingConfiguration(interval: 0.5, with: 2)
let pinger = try SwiftyPing(host: "1.1.1.1", configuration: config, queue: .global())

pinger.observer = { response in
    print("seq=\(response.trueSequenceNumber) time=\(response.duration)")
}

pinger.finished = { result in
    print("transmitted=\(result.packetsTransmitted) received=\(result.packetsReceived)")
}

try pinger.startPinging()
```

### Ping once

```swift
import SwiftyPing

let config = PingConfiguration(interval: 1, with: 2)
let pinger = try SwiftyPing(host: "1.1.1.1", configuration: config, queue: .global())

pinger.targetCount = 1
pinger.observer = { response in
    print(response.duration)
}

try pinger.startPinging()
```

## Async/Await API

SwiftyPing now includes async methods equivalent to `observer` and `finished`.

### Receive responses as an async stream

```swift
import SwiftyPing

let config = PingConfiguration(interval: 0.5, with: 2)
let pinger = try SwiftyPing(host: "1.1.1.1", configuration: config, queue: .global())
pinger.targetCount = 5

Task {
    for await response in pinger.responseStream() {
        print("stream seq=\(response.trueSequenceNumber) time=\(response.duration)")
    }
}

try pinger.startPinging()
```

### Await final ping result

```swift
import SwiftyPing

let config = PingConfiguration(interval: 0.5, with: 2)
let pinger = try SwiftyPing(host: "1.1.1.1", configuration: config, queue: .global())
pinger.targetCount = 5

try pinger.startPinging()
let result = await pinger.waitForFinishedResult()

print("packetLoss=\(String(describing: result.packetLoss))")
```

### Full async example

```swift
import SwiftyPing

let config = PingConfiguration(interval: 0.5, with: 2)
let pinger = try SwiftyPing(host: "1.1.1.1", configuration: config, queue: .global())
pinger.targetCount = 10

let streamTask = Task {
    for await response in pinger.responseStream() {
        print("reply #\(response.trueSequenceNumber): \(response.duration)s")
    }
}

try pinger.startPinging()
let result = await pinger.waitForFinishedResult()

streamTask.cancel()
print("done: tx=\(result.packetsTransmitted), rx=\(result.packetsReceived)")
```

## Parallel usage

Each `SwiftyPing` instance has isolated internal state, so multiple instances can run concurrently (for example with `withTaskGroup`) without interfering with each other.

Important: parallel execution is supported only across different `SwiftyPing` instances. If `startPinging` is called simultaneously on the same instance, behavior remains one active ping session per instance.

```swift
import SwiftyPing

let hosts = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

await withTaskGroup(of: Void.self) { group in
    for host in hosts {
        group.addTask {
            do {
                let pinger = try SwiftyPing(
                    host: host,
                    configuration: PingConfiguration(interval: 0.5, with: 2),
                    queue: .global()
                )
                pinger.targetCount = 3
                try pinger.startPinging()
                let result = await pinger.waitForFinishedResult()
                print("\(host): tx=\(result.packetsTransmitted), rx=\(result.packetsReceived)")
            } catch {
                print("\(host): \(error)")
            }
        }
    }
}
```

## Notes

- Callback API (`observer`, `finished`, `delegate`) remains available.
- Async API is additive and can be used together with callbacks.
- The library is updated to a modern Swift style with Swift concurrency support and stricter sendability checks.

## License

MIT
