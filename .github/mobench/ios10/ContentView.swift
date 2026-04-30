import UIKit

private struct ProfileLaunchOptions {
    let benchDelayMs: UInt64
    let resultHoldMs: UInt64
    let repeatUntilMs: UInt64
    let warmupOnly: Bool

    static func resolved() -> ProfileLaunchOptions {
        let info = ProcessInfo.processInfo

        var benchDelayMs = UInt64(info.environment["MOBENCH_BENCH_DELAY_MS"] ?? "0") ?? 0
        var resultHoldMs = UInt64(
            info.environment["MOBENCH_PROFILE_RESULT_HOLD_MS"] ?? "5000"
        ) ?? 5000
        var repeatUntilMs = UInt64(
            info.environment["MOBENCH_PROFILE_REPEAT_UNTIL_MS"] ?? "0"
        ) ?? 0
        var warmupOnly = info.environment["MOBENCH_PROFILE_WARMUP_ONLY"] == "1"

        for arg in info.arguments {
            if arg.hasPrefix("--mobench-profile-bench-delay-ms="),
               let value = arg.split(separator: "=", maxSplits: 1).last,
               let parsed = UInt64(value) {
                benchDelayMs = parsed
            } else if arg.hasPrefix("--mobench-profile-result-hold-ms="),
                      let value = arg.split(separator: "=", maxSplits: 1).last,
                      let parsed = UInt64(value) {
                resultHoldMs = parsed
            } else if arg.hasPrefix("--mobench-profile-repeat-until-ms="),
                      let value = arg.split(separator: "=", maxSplits: 1).last,
                      let parsed = UInt64(value) {
                repeatUntilMs = parsed
            } else if arg == "--mobench-profile-warmup-only"
                || arg == "--mobench-profile-warmup-only=1" {
                warmupOnly = true
            }
        }

        NSLog(
            "[BenchRunner] Profile launch options: delayMs=%llu, repeatUntilMs=%llu, resultHoldMs=%llu, warmupOnly=%@",
            benchDelayMs,
            repeatUntilMs,
            resultHoldMs,
            warmupOnly ? "true" : "false"
        )

        return ProfileLaunchOptions(
            benchDelayMs: benchDelayMs,
            resultHoldMs: resultHoldMs,
            repeatUntilMs: repeatUntilMs,
            warmupOnly: warmupOnly
        )
    }
}

final class BenchRunnerViewController: UIViewController {
    private let reportLabel = UILabel()
    private let completedLabel = UILabel()
    private let jsonLabel = UILabel()
    private let stack = UIStackView()
    private var started = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .white

        reportLabel.accessibilityIdentifier = "benchmarkReport"
        reportLabel.font = UIFont(name: "Menlo", size: 13) ?? UIFont.systemFont(ofSize: 13)
        reportLabel.numberOfLines = 0
        reportLabel.text = "Running benchmarks..."

        completedLabel.accessibilityIdentifier = "benchmarkCompleted"
        completedLabel.isAccessibilityElement = true
        completedLabel.text = ""
        completedLabel.accessibilityLabel = ""

        jsonLabel.accessibilityIdentifier = "benchmarkReportJSON"
        jsonLabel.isAccessibilityElement = true
        jsonLabel.text = ""
        jsonLabel.accessibilityLabel = ""
        jsonLabel.numberOfLines = 1

        stack.addArrangedSubview(reportLabel)
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 28),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: view.bottomAnchor, constant: -12)
        ])
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard !started else {
            return
        }
        started = true

        DispatchQueue.global(qos: .userInitiated).async {
            let options = ProfileLaunchOptions.resolved()
            if options.benchDelayMs > 0 {
                Thread.sleep(forTimeInterval: Double(options.benchDelayMs) / 1_000.0)
            }

            let repeatDeadline = Date().addingTimeInterval(
                Double(options.repeatUntilMs) / 1_000.0
            )
            var repeatedRuns = 1
            var result = BenchRunnerFFI.runCurrentBenchmark()
            while !options.warmupOnly && options.repeatUntilMs > 0 && Date() < repeatDeadline {
                result = BenchRunnerFFI.runCurrentBenchmark()
                repeatedRuns += 1
            }

            DispatchQueue.main.async {
                self.reportLabel.text = result.displayText
                self.jsonLabel.text = result.jsonReport
                self.jsonLabel.accessibilityLabel = result.jsonReport
                self.completedLabel.text = "completed"
                self.completedLabel.accessibilityLabel = "completed"
                if self.completedLabel.superview == nil {
                    self.stack.addArrangedSubview(self.completedLabel)
                    self.stack.addArrangedSubview(self.jsonLabel)
                }
            }

            NSLog("BENCH_REPORT_JSON_START")
            NSLog("%@", result.jsonReport)
            NSLog("BENCH_REPORT_JSON_END")
            if repeatedRuns > 1 {
                NSLog("Repeated benchmark %d time(s) during profile capture", repeatedRuns)
            }

            if options.warmupOnly {
                NSLog("Warmup-only profile run complete")
                return
            }

            NSLog("Displaying results for \(options.resultHoldMs) ms for capture output...")
            Thread.sleep(forTimeInterval: Double(options.resultHoldMs) / 1_000.0)
            NSLog("Display hold complete")
        }
    }
}
