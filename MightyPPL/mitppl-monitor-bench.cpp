#include "MightyPPLMonitor.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

    struct CliOptions {
        std::string formula;
        std::string formula_file;
        std::string input_file;
        std::string case_name = "unnamed";
        mightypplcpp::MonitorBackend backend = mightypplcpp::MonitorBackend::ConcreteProjected;
    };

    void print_usage(std::ostream& out) {
        out << "Usage:\n"
            << "  mitppl-monitor-bench --formula '<formula>' --input events.txt [--case-name name] [--monitor-backend concrete|bdd]\n"
            << "  mitppl-monitor-bench --formula-file formula.mitl --input events.txt [--case-name name] [--monitor-backend concrete|bdd]\n";
    }

    CliOptions parse_args(int argc, char** argv) {
        CliOptions options;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--formula") {
                if (++i >= argc) {
                    throw std::runtime_error("--formula requires an argument");
                }
                options.formula = argv[i];
            } else if (arg == "--formula-file") {
                if (++i >= argc) {
                    throw std::runtime_error("--formula-file requires an argument");
                }
                options.formula_file = argv[i];
            } else if (arg == "--input") {
                if (++i >= argc) {
                    throw std::runtime_error("--input requires an argument");
                }
                options.input_file = argv[i];
            } else if (arg == "--case-name") {
                if (++i >= argc) {
                    throw std::runtime_error("--case-name requires an argument");
                }
                options.case_name = argv[i];
            } else if (arg == "--monitor-backend") {
                if (++i >= argc) {
                    throw std::runtime_error("--monitor-backend requires an argument");
                }
                options.backend = mightypplcpp::parse_monitor_backend(argv[i]);
            } else if (arg == "--help" || arg == "-h") {
                print_usage(std::cout);
                std::exit(0);
            } else {
                throw std::runtime_error("unknown option: " + arg);
            }
        }

        if (options.formula.empty() == options.formula_file.empty()) {
            throw std::runtime_error("provide exactly one of --formula or --formula-file");
        }
        if (options.input_file.empty()) {
            throw std::runtime_error("--input is required");
        }
        return options;
    }

    std::string read_formula_file(const std::string& path) {
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("could not open formula file: " + path);
        }
        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

    std::string json_escape(const std::string& text) {
        std::ostringstream out;
        for (char c : text) {
            switch (c) {
                case '\\': out << "\\\\"; break;
                case '"': out << "\\\""; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default: out << c; break;
            }
        }
        return out.str();
    }

    double millis_between(const std::chrono::steady_clock::time_point& begin,
                          const std::chrono::steady_clock::time_point& end) {
        return std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - begin).count();
    }

} // namespace

int main(int argc, char** argv) {
    try {
        const CliOptions cli = parse_args(argc, argv);
        const std::string formula = cli.formula.empty() ? read_formula_file(cli.formula_file) : cli.formula;

        mightypplcpp::CompileOptions compile_options;
        compile_options.infinite = true;
        compile_options.verbose = false;

        mightypplcpp::FeedbackSettings feedback_settings;
        feedback_settings.enabled_channels = 0;

        using clock_t = std::chrono::steady_clock;

        std::optional<mightypplcpp::PropertyBundle> concrete_bundle;
        std::optional<mightypplcpp::BddPropertyBundle> bdd_bundle;

        const auto compile_begin = clock_t::now();
        if (cli.backend == mightypplcpp::MonitorBackend::NativeBdd) {
            bdd_bundle.emplace(mightypplcpp::compile_bdd_property_bundle_from_formula(formula, compile_options));
        } else {
            concrete_bundle.emplace(mightypplcpp::compile_property_bundle_from_formula(formula, compile_options));
        }
        const auto compile_end = clock_t::now();

        const auto monitor_begin = clock_t::now();
        std::optional<mightypplcpp::MonitorSession> session;
        if (cli.backend == mightypplcpp::MonitorBackend::NativeBdd) {
            session.emplace(std::move(*bdd_bundle), feedback_settings);
        } else {
            session.emplace(std::move(*concrete_bundle), feedback_settings, cli.backend);
        }
        const auto monitor_end = clock_t::now();

        std::ifstream input(cli.input_file);
        if (!input) {
            throw std::runtime_error("could not open input file: " + cli.input_file);
        }
        mightypplcpp::FileEventSource source(input, cli.input_file);

        std::vector<std::string> verdict_trace;
        std::size_t events_seen = 0;
        std::size_t max_active_states = 0;
        double total_replay_ms = 0.0;
        double max_event_ms = 0.0;
        std::optional<std::size_t> first_decisive_verdict_index;

        while (auto event = source.next()) {
            const auto event_begin = clock_t::now();
            const auto frame = session->step(*event);
            const auto event_end = clock_t::now();

            const double event_ms = millis_between(event_begin, event_end);
            total_replay_ms += event_ms;
            max_event_ms = std::max(max_event_ms, event_ms);

            verdict_trace.push_back(mightypplcpp::monitor_answer_name(frame.verdict));
            ++events_seen;

            max_active_states = std::max(max_active_states, session->total_active_state_count());
            if (!first_decisive_verdict_index.has_value() && frame.verdict != monitaal::INCONCLUSIVE) {
                first_decisive_verdict_index = events_seen;
            }
        }

        const double avg_event_ms = events_seen == 0 ? 0.0 : total_replay_ms / static_cast<double>(events_seen);

        std::ostringstream json;
        json << std::fixed << std::setprecision(6);
        json << "{"
             << "\"case_name\":\"" << json_escape(cli.case_name) << "\","
             << "\"backend\":\"" << json_escape(mightypplcpp::monitor_backend_name(cli.backend)) << "\","
             << "\"compile_setup_ms\":" << millis_between(compile_begin, compile_end) << ","
             << "\"accepting_space_precompute_ms\":" << millis_between(monitor_begin, monitor_end) << ","
             << "\"total_replay_ms\":" << total_replay_ms << ","
             << "\"avg_per_event_ms\":" << avg_event_ms << ","
             << "\"max_per_event_ms\":" << max_event_ms << ","
             << "\"events_seen\":" << events_seen << ","
             << "\"max_active_states\":" << max_active_states << ","
             << "\"first_decisive_verdict_index\":";
        if (first_decisive_verdict_index.has_value()) {
            json << *first_decisive_verdict_index;
        } else {
            json << "null";
        }
        json << ",\"final_verdict\":\"" << json_escape(mightypplcpp::monitor_answer_name(session->verdict())) << "\","
             << "\"verdict_trace\":[";
        for (std::size_t i = 0; i < verdict_trace.size(); ++i) {
            if (i != 0) {
                json << ",";
            }
            json << "\"" << json_escape(verdict_trace[i]) << "\"";
        }
        json << "]}";

        std::cout << json.str() << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "mitppl-monitor-bench: " << e.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
