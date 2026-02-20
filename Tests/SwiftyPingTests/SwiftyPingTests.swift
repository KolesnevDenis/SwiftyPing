import Foundation
import Testing
@testable import SwiftyPing

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() {
        lock.lock()
        value += 1
        lock.unlock()
    }

    func get() -> Int {
        lock.lock()
        let current = value
        lock.unlock()
        return current
    }
}

private final class LockedResultStore: @unchecked Sendable {
    private let lock = NSLock()
    private var value: PingResult?

    func set(_ newValue: PingResult) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    func get() -> PingResult? {
        lock.lock()
        let current = value
        lock.unlock()
        return current
    }
}

private func waitUntil(
    timeoutNanoseconds: UInt64 = 3_000_000_000,
    checkIntervalNanoseconds: UInt64 = 20_000_000,
    _ condition: @escaping @Sendable () -> Bool
) async -> Bool {
    let start = DispatchTime.now().uptimeNanoseconds
    while DispatchTime.now().uptimeNanoseconds - start < timeoutNanoseconds {
        if condition() {
            return true
        }
        try? await Task.sleep(nanoseconds: checkIntervalNanoseconds)
    }
    return condition()
}

private func makePinger(
    host: String = "1.1.1.1",
    interval: TimeInterval = 0.05,
    timeout: TimeInterval = 1,
    targetCount: Int? = nil,
    haltAfterTarget: Bool = false
) throws -> SwiftyPing {
    var config = PingConfiguration(interval: interval, with: timeout)
    config.haltAfterTarget = haltAfterTarget
    let pinger = try SwiftyPing(host: host, configuration: config, queue: .global())
    pinger.targetCount = targetCount
    return pinger
}

@Test func pingConfigurationInitializers() {
    let defaultConfig = PingConfiguration()
    #expect(defaultConfig.pingInterval == 1)
    #expect(defaultConfig.timeoutInterval == 5)
    #expect(defaultConfig.handleBackgroundTransitions)
    #expect(defaultConfig.payloadSize == MemoryLayout<uuid_t>.size)
    #expect(defaultConfig.haltAfterTarget)

    let custom = PingConfiguration(interval: 0.25, with: 2)
    #expect(custom.pingInterval == 0.25)
    #expect(custom.timeoutInterval == 2)

    let onlyInterval = PingConfiguration(interval: 0.3)
    #expect(onlyInterval.pingInterval == 0.3)
    #expect(onlyInterval.timeoutInterval == 5)
}

@Test func pingResultPacketLoss() {
    let empty = PingResult(responses: [], packetsTransmitted: 0, packetsReceived: 0, roundtrip: nil)
    #expect(empty.packetLoss == nil)

    let nonEmpty = PingResult(responses: [], packetsTransmitted: 10, packetsReceived: 7, roundtrip: nil)
    #expect(nonEmpty.packetLoss != nil)
    #expect(abs((nonEmpty.packetLoss ?? 0) - 0.3) < 0.000_001)
}

@Test func destinationResolutionAndProperties() throws {
    let data = try SwiftyPing.Destination.getIPv4AddressFromHost(host: "google.com")
    let destination = SwiftyPing.Destination(host: "google.com", ipv4Address: data)

    #expect(destination.host == "google.com")
    #expect(destination.socketAddress != nil)
    #expect(destination.ip != nil)
}

@Test func destinationResolveInvalidHostThrows() {
    do {
        _ = try SwiftyPing.Destination.getIPv4AddressFromHost(host: "this-host-should-not-exist.invalid")
        #expect(Bool(false), "Expected invalid host resolution to throw")
    } catch {
        #expect(error is PingError)
    }
}

@Test func socketInfoInitialization() throws {
    let pinger = try makePinger()
    let info = SocketInfo(pinger: pinger, identifier: 42)

    #expect(info.identifier == 42)
    #expect(info.pinger != nil)
}

@Test func pingerInitializers() throws {
    let config = PingConfiguration(interval: 0.1, with: 1)

    let fromHost = try SwiftyPing(host: "google.com", configuration: config, queue: .global())
    #expect(fromHost.configuration.pingInterval == 0.1)
    #expect(fromHost.configuration.timeoutInterval == 1)
    #expect(fromHost.destination.socketAddress != nil)

    let fromIPv4 = try SwiftyPing(ipv4Address: "1.1.1.1", config: config, queue: .global())
    #expect(fromIPv4.destination.host == "1.1.1.1")
    #expect(fromIPv4.destination.socketAddress != nil)

    let destination = try SwiftyPing.Destination(host: "google.com", ipv4Address: SwiftyPing.Destination.getIPv4AddressFromHost(host: "google.com"))
    let fromDestination = try SwiftyPing(destination: destination, configuration: config, queue: .global())
    #expect(fromDestination.destination.host == "google.com")
}

@Test func asyncResponseStreamAndWaitForFinishedResult() async throws {
    let pinger = try makePinger(targetCount: 1)

    let firstResponseTask = Task<PingResponse?, Never> {
        for await response in pinger.responseStream() {
            return response
        }
        return nil
    }

    try pinger.startPinging()
    let result = await pinger.waitForFinishedResult()
    let firstResponse = await firstResponseTask.value

    #expect(firstResponse != nil)
    #expect(result.packetsTransmitted == 1)
    #expect(result.responses.count == 1)
    #expect(pinger.currentCount >= 1)
}

@Test func observerAndFinishedClosures() async throws {
    let pinger = try makePinger(targetCount: 1)

    let observerCounter = LockedCounter()
    let finishedCounter = LockedCounter()
    let finishedResultStore = LockedResultStore()

    pinger.observer = { _ in
        observerCounter.increment()
    }

    pinger.finished = { result in
        finishedResultStore.set(result)
        finishedCounter.increment()
    }

    try pinger.startPinging()
    _ = await pinger.waitForFinishedResult()

    let observerCalled = await waitUntil { observerCounter.get() > 0 }
    let finishedCalled = await waitUntil { finishedCounter.get() > 0 }

    #expect(observerCalled)
    #expect(finishedCalled)
    #expect(finishedResultStore.get()?.packetsTransmitted == 1)
}

@Test func stopPingingResetBehavior() async throws {
    let pinger = try makePinger(targetCount: 1)
    try pinger.startPinging()

    _ = await pinger.waitForFinishedResult()
    #expect(pinger.currentCount == 1)

    pinger.stopPinging(resetSequence: false)
    #expect(pinger.currentCount == 1)

    pinger.stopPinging(resetSequence: true)
    #expect(pinger.currentCount == 0)
}

@Test func haltPingingAllowsRestart() async throws {
    let pinger = try makePinger(targetCount: 1)

    try pinger.startPinging()
    let first = await pinger.waitForFinishedResult()
    #expect(first.packetsTransmitted == 1)

    pinger.haltPinging(resetSequence: true)

    pinger.targetCount = 1
    try pinger.startPinging()
    let second = await pinger.waitForFinishedResult()
    #expect(second.packetsTransmitted == 1)
}

@Test func delegateReceivesResponse() async throws {
    final class Delegate: PingDelegate {
        let counter: LockedCounter

        init(counter: LockedCounter) {
            self.counter = counter
        }

        func didReceive(response: PingResponse) {
            counter.increment()
        }
    }

    let pinger = try makePinger(targetCount: 1)
    let counter = LockedCounter()
    let delegate = Delegate(counter: counter)
    pinger.delegate = delegate

    try pinger.startPinging()
    _ = await pinger.waitForFinishedResult()

    let delegateCalled = await waitUntil { counter.get() > 0 }
    #expect(delegateCalled)
}

@Test func dataSocketAddressExtensions() {
    var socketAddress = sockaddr_in()
    socketAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    socketAddress.sin_family = UInt8(AF_INET)
    socketAddress.sin_port = in_port_t(8080).bigEndian
    socketAddress.sin_addr.s_addr = inet_addr("1.1.1.1")

    let data = Data(bytes: &socketAddress, count: MemoryLayout<sockaddr_in>.size)
    let internet = data.socketAddressInternet
    let generic = data.socketAddress

    #expect(internet.sin_family == UInt8(AF_INET))
    #expect(generic.sa_family == sa_family_t(AF_INET))
}

@Test func icmpTypeRawValues() {
    #expect(ICMPType.EchoReply.rawValue == 0)
    #expect(ICMPType.EchoRequest.rawValue == 8)
}

@Test func pingErrorEquatable() {
    #expect(
        PingError.checksumMismatch(received: 1, calculated: 2)
        == PingError.checksumMismatch(received: 1, calculated: 2)
    )
    #expect(PingError.hostNotFound != PingError.unknownHostError)
}

@Test func stressParallelWithTaskGroupMultiplePingers() async throws {
    let hosts = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "google.com", "one.one.one.one"]
    let targetCount = 3

    let results = try await withThrowingTaskGroup(of: PingResult.self, returning: [PingResult].self) { group in
        for host in hosts {
            group.addTask {
                let pinger = try makePinger(host: host, interval: 0.03, timeout: 1.2, targetCount: targetCount, haltAfterTarget: false)
                try pinger.startPinging()
                return await pinger.waitForFinishedResult()
            }
        }

        var collected: [PingResult] = []
        for try await result in group {
            collected.append(result)
        }
        return collected
    }

    #expect(results.count == hosts.count)
    for result in results {
        #expect(result.packetsTransmitted == UInt64(targetCount))
        #expect(result.responses.count == targetCount)
    }
}

@Test func stressParallelWithTaskGroupHighInstanceCount() async throws {
    let instanceCount = 30
    let hosts = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "94.140.14.14"]

    let initializedFlags = try await withThrowingTaskGroup(of: Bool.self, returning: [Bool].self) { group in
        for index in 0..<instanceCount {
            let host = hosts[index % hosts.count]
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(index % 8) * 20_000_000)
                let pinger = try makePinger(host: host, interval: 0.03, timeout: 1.2, targetCount: 1, haltAfterTarget: false)
                let initialized = pinger.destination.socketAddress != nil
                pinger.haltPinging(resetSequence: true)
                return initialized
            }
        }

        var collected: [Bool] = []
        collected.reserveCapacity(instanceCount)
        for try await initialized in group {
            collected.append(initialized)
        }
        return collected
    }

    #expect(initializedFlags.count == instanceCount)
    for initialized in initializedFlags {
        #expect(initialized)
    }
}
