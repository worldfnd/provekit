#!/usr/bin/env bun

const [swiftPath] = Bun.argv.slice(2);
if (!swiftPath) {
  throw new Error("usage: patch-ios-remote-proving-key.ts <BenchRunnerFFI.swift>");
}

const marker = "private enum RemoteProvingKey";
let swift = await Bun.file(swiftPath).text();
if (swift.includes(marker)) {
  console.log(`Remote proving-key bootstrap already present in ${swiftPath}`);
  process.exit(0);
}

swift = swift.replace("import Foundation\nimport Darwin\n", `import Foundation
import Darwin
import CryptoKit

${marker} {
    private struct Manifest: Decodable {
        let url: String
        let bytes: UInt64
        let sha256: String
    }

    static func prepareIfConfigured() throws {
        guard let manifestURL = Bundle.main.url(
            forResource: "proving_key_remote",
            withExtension: "json"
        ) else {
            return
        }
        let manifest = try JSONDecoder().decode(
            Manifest.self,
            from: Data(contentsOf: manifestURL)
        )
        guard let remoteURL = URL(string: manifest.url),
              remoteURL.scheme == "https" else {
            throw failure("remote proving-key URL must use HTTPS")
        }

        let manager = FileManager.default
        let root = try manager.url(
            for: .cachesDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("mobench-groth16", isDirectory: true)
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        let provingKey = root.appendingPathComponent("proving_key.zkey")

        var reusable = false
        if let attributes = try? manager.attributesOfItem(atPath: provingKey.path),
           let size = attributes[.size] as? NSNumber,
           size.uint64Value == manifest.bytes {
            reusable = try sha256(provingKey) == manifest.sha256.lowercased()
        }
        if !reusable {
            NSLog("MOBENCH_REMOTE_ZKEY_DOWNLOAD_START %@", remoteURL.absoluteString)
            let semaphore = DispatchSemaphore(value: 0)
            var downloaded: URL?
            var downloadError: Error?
            URLSession.shared.downloadTask(with: remoteURL) { url, _, error in
                downloaded = url
                downloadError = error
                semaphore.signal()
            }.resume()
            semaphore.wait()
            if let downloadError {
                throw downloadError
            }
            guard let downloaded else {
                throw failure("remote proving-key download returned no file")
            }
            let size = try manager.attributesOfItem(atPath: downloaded.path)[.size] as? NSNumber
            guard size?.uint64Value == manifest.bytes else {
                throw failure("remote proving-key byte length mismatch")
            }
            guard try sha256(downloaded) == manifest.sha256.lowercased() else {
                throw failure("remote proving-key SHA-256 mismatch")
            }
            if manager.fileExists(atPath: provingKey.path) {
                try manager.removeItem(at: provingKey)
            }
            try manager.moveItem(at: downloaded, to: provingKey)
            NSLog("MOBENCH_REMOTE_ZKEY_DOWNLOAD_COMPLETE %llu", manifest.bytes)
        }

        for name in ["reference.wtns", "verification_key.json"] {
            let source = Bundle.main.url(
                forResource: (name as NSString).deletingPathExtension,
                withExtension: (name as NSString).pathExtension
            )
            guard let source else {
                continue
            }
            let destination = root.appendingPathComponent(name)
            if manager.fileExists(atPath: destination.path) {
                try manager.removeItem(at: destination)
            }
            try manager.copyItem(at: source, to: destination)
        }
        root.path.withCString {
            _ = setenv("MOBENCH_GROTH16_FIXTURE_ROOT", $0, 1)
        }
        provingKey.path.withCString {
            _ = setenv("MOBENCH_WEBAUTHN_ZKEY", $0, 1)
        }
    }

    private static func sha256(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard fcntl(handle.fileDescriptor, F_NOCACHE, 1) != -1 else {
            throw NSError(
                domain: NSPOSIXErrorDomain,
                code: Int(errno),
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "failed to disable proving-key file caching"
                ]
            )
        }
        var hasher = SHA256()
        while try autoreleasepool(invoking: {
            guard let data = try handle.read(upToCount: 8 * 1024 * 1024),
                  !data.isEmpty else {
                return false
            }
            hasher.update(data: data)
            return true
        }) {}
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func failure(_ message: String) -> NSError {
        NSError(
            domain: "dev.world.provekit.remote-proving-key",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
`);

swift = swift.replace(
  `    static func runCurrentBenchmark() -> BenchmarkResult {
        let params = BenchParams.resolved()
        return run(params: params)
    }`,
  `    static func runCurrentBenchmark() -> BenchmarkResult {
        do {
            try RemoteProvingKey.prepareIfConfigured()
        } catch {
            let message = "Remote proving-key preparation failed: \\(error.localizedDescription)"
            print("[BenchRunner] ERROR: \\(message)")
            return BenchmarkResult(
                displayText: message,
                jsonReport: serializeJSON(["error": true, "message": message])
            )
        }
        let params = BenchParams.resolved()
        return run(params: params)
    }`,
);

if (!swift.includes(marker) || !swift.includes("RemoteProvingKey.prepareIfConfigured()")) {
  throw new Error(`failed to patch ${swiftPath}`);
}
await Bun.write(swiftPath, swift);
console.log(`Added hash-checked remote proving-key bootstrap to ${swiftPath}`);
