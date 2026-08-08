import { resolve } from "node:path";

const [sourceArgument, countArgument] = process.argv.slice(2);
if (!sourceArgument || !countArgument) {
  throw new Error("usage: bun patch-ios-cold-launches.ts BenchRunnerUITests.swift COUNT");
}

const sourcePath = resolve(sourceArgument);
const count = Number(countArgument);
if (!Number.isInteger(count) || count < 2) throw new Error("COUNT must be an integer greater than one");

const source = await Bun.file(sourcePath).text();
const startMarker = "    func testLaunchAndCaptureBenchmarkReport() {";
const endMarker = "\n    // Keep the old test name for backward compatibility";
const start = source.indexOf(startMarker);
const end = source.indexOf(endMarker, start);
if (start < 0 || end < 0) throw new Error(`${sourcePath}: Mobench XCTest function markers not found`);

const replacement = `    func testLaunchAndCaptureBenchmarkReport() {
        var reports: [Any] = []

        for invocation in 0..<${count} {
            let app = XCUIApplication()
            if app.state != .notRunning {
                app.terminate()
            }
            app.launch()

            let completedIndicator = app.staticTexts["benchmarkCompleted"]
            let completed = waitForBenchmarkCompletion(completedIndicator, app: app)
            XCTAssertTrue(
                completed,
                "Cold invocation \\(invocation) should complete within \\(benchmarkTimeout) seconds"
            )

            Thread.sleep(forTimeInterval: 5.0)
            let reportElement = app.staticTexts["benchmarkReportJSON"]
            XCTAssertTrue(
                reportElement.exists,
                "Cold invocation \\(invocation) report JSON should exist"
            )
            let reportValue = reportElement.value as? String
            let jsonString = firstValidJSON([reportValue, reportElement.label]) ?? ""
            XCTAssertFalse(jsonString.isEmpty, "Cold invocation \\(invocation) report should not be empty")
            XCTAssertFalse(
                jsonString.contains("\\\"error\\\""),
                "Cold invocation \\(invocation) should not return an error payload: \\(jsonString)"
            )
            guard let data = jsonString.data(using: .utf8),
                  let report = try? JSONSerialization.jsonObject(with: data) else {
                XCTFail("Cold invocation \\(invocation) report should be valid JSON")
                return
            }
            reports.append(report)
            app.terminate()
        }

        guard let aggregateData = try? JSONSerialization.data(withJSONObject: reports),
              let aggregate = String(data: aggregateData, encoding: .utf8) else {
            XCTFail("Cold benchmark reports should serialize as JSON")
            return
        }
        NSLog("BENCH_REPORT_JSON_START")
        NSLog("%@", aggregate)
        NSLog("BENCH_REPORT_JSON_END")
        print("BENCH_REPORT_JSON_START")
        print(aggregate)
        print("BENCH_REPORT_JSON_END")
        XCTAssertEqual(reports.count, ${count}, "Every cold app launch should produce one report")
    }
`;

await Bun.write(sourcePath, source.slice(0, start) + replacement + source.slice(end));
console.log(`${sourcePath}: patched for ${count} fresh app launches`);
