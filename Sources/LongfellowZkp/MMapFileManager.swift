//
//  MMapFileManager.swift
//  LongfellowZkp
//
//  Copyright © 2026 EUDIW. All rights reserved.
//

import Foundation

/// Manages a memory-mapped file in the app group shared container.
///
/// The mapped pointer is exposed as `nonisolated(unsafe)` so that it can be
/// read from synchronous contexts (e.g. the ZK prover) after `createAndMap()`
/// has been called.  Callers must ensure `createAndMap()` completes before
/// reading `mappedPointer`.
public actor MMapFileManager {
    public static let appGroupIdentifier = "group.longfellow"
    public static let fileName = "shared_mmap.bin"
    public static let fileSize: Int = 1_073_741_824 // 1 GB

    private var fileDescriptor: Int32 = -1
    public nonisolated(unsafe) private(set) var mappedPointer: UnsafeMutableRawPointer?
    public private(set) var fileURL: URL?

    public init() {}

    /// Creates (if needed) a 1 GB file in group storage and memory-maps it.
    /// - Returns: A raw pointer to the mapped region.
    @discardableResult
    public func createAndMap() throws -> UnsafeMutableRawPointer {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupIdentifier
        ) else {
            throw MMapError.appGroupNotAvailable
        }

        let url = containerURL.appendingPathComponent(Self.fileName)
        self.fileURL = url

        // Create the file if it doesn't exist
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }

        // Open the file
        let fd = open(url.path, O_RDWR)
        guard fd >= 0 else {
            throw MMapError.openFailed(errno: errno)
        }
        self.fileDescriptor = fd

        // Extend file to 1 GB using ftruncate
        let result = ftruncate(fd, off_t(Self.fileSize))
        guard result == 0 else {
            close(fd)
            self.fileDescriptor = -1
            throw MMapError.truncateFailed(errno: errno)
        }

        // Memory-map the file
        let ptr = mmap(nil, Self.fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
        guard ptr != MAP_FAILED else {
            close(fd)
            self.fileDescriptor = -1
            throw MMapError.mmapFailed(errno: errno)
        }

        self.mappedPointer = ptr
        return ptr!
    }

    /// Syncs the mapped memory back to disk.
    public func sync() throws {
        guard let ptr = mappedPointer else {
            throw MMapError.notMapped
        }
        let result = msync(ptr, Self.fileSize, MS_SYNC)
        guard result == 0 else {
            throw MMapError.msyncFailed(errno: errno)
        }
    }

    /// Unmaps the memory and closes the file descriptor.
    public func unmap() {
        if let ptr = mappedPointer {
            munmap(ptr, Self.fileSize)
            mappedPointer = nil
        }
        if fileDescriptor >= 0 {
            close(fileDescriptor)
            fileDescriptor = -1
        }
    }
}

public enum MMapError: Error, LocalizedError {
    case appGroupNotAvailable
    case openFailed(errno: Int32)
    case truncateFailed(errno: Int32)
    case mmapFailed(errno: Int32)
    case notMapped
    case msyncFailed(errno: Int32)

    public var errorDescription: String? {
        switch self {
        case .appGroupNotAvailable:
            "App group container not available"
        case .openFailed(let code):
            "Failed to open file (errno: \(code))"
        case .truncateFailed(let code):
            "Failed to truncate file to 1 GB (errno: \(code))"
        case .mmapFailed(let code):
            "mmap failed (errno: \(code))"
        case .notMapped:
            "File is not currently memory-mapped"
        case .msyncFailed(let code):
            "msync failed (errno: \(code))"
        }
    }
}
