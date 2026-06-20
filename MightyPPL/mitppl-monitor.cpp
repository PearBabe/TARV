#include "MightyPPLMonitor.h"

#include "Monitor.h"
#include "state.h"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <functional>

namespace {

    struct CliOptions {
        std::string formula;
        std::string formula_file;
        std::string input_file;
        std::string feedback_jsonl;
        std::string feedback_channels = "all";
        std::string campaign = "standalone-monitor";
        std::string subject = "unknown-subject";
        std::string fuzzer_name = "bizonefuzz++";
        std::string mode = "full";
        std::string run_id = "run-0";
        std::string property_set_id = "property-set-0";
        mightypplcpp::SatisfiabilitySemantics sat_semantics = mightypplcpp::SatisfiabilitySemantics::Infinite;
        mightypplcpp::MonitorBackend backend = mightypplcpp::MonitorBackend::ConcreteProjected;
        bool sat_semantics_set = false;
        bool verbose = false;
        bool help = false;
        bool disable_concrete_slack = false;
        bool log_internal_anchor = false;
        bool skip_sat_precheck = false;
        bool ignore_unknown_propositions = false;
        std::uint32_t near_deadline_threshold_ms = 5;
        std::size_t exact_slack_frontier_limit = 16;
    };

    void print_usage(std::ostream& out) {
        out << "Usage:\n"
            << "  mitppl-monitor --formula '<formula>' [--monitor-backend concrete|bdd] [--sat-inf|--sat-fin] [--skip-sat-precheck] [--ignore-unknown-propositions] [--input events.txt] [--feedback-jsonl out.jsonl] [--feedback-channels all] [--campaign id] [--subject name] [--fuzzer-name name] [--mode full] [--run-id id] [--property-set-id id] [--verbose]\n"
            << "  mitppl-monitor <formula-file> [--monitor-backend concrete|bdd] [--sat-inf|--sat-fin] [--skip-sat-precheck] [--ignore-unknown-propositions] [--input events.txt] [--feedback-jsonl out.jsonl] [--feedback-channels all] [--campaign id] [--subject name] [--fuzzer-name name] [--mode full] [--run-id id] [--property-set-id id] [--verbose]\n\n"
            << "Events are read as '@0 a,b', '@5 -', or '@[10,12] a'.\n";
    }

    void set_sat_semantics(CliOptions& options, mightypplcpp::SatisfiabilitySemantics semantics) {
        if (options.sat_semantics_set) {
            throw std::runtime_error("--sat-inf and --sat-fin are mutually exclusive and may only be specified once");
        }
        options.sat_semantics = semantics;
        options.sat_semantics_set = true;
    }

    const char* sat_semantics_description(mightypplcpp::SatisfiabilitySemantics semantics) {
        return semantics == mightypplcpp::SatisfiabilitySemantics::Finite
               ? "finite timed words"
               : "infinite timed words";
    }

    CliOptions parse_args(int argc, const char** argv) {
        CliOptions options;

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                options.help = true;
            } else if (arg == "--formula") {
                if (++i >= argc) {
                    throw std::runtime_error("--formula requires an argument");
                }
                options.formula = argv[i];
            } else if (arg == "--input") {
                if (++i >= argc) {
                    throw std::runtime_error("--input requires an argument");
                }
                options.input_file = argv[i];
            } else if (arg == "--feedback-jsonl") {
                if (++i >= argc) {
                    throw std::runtime_error("--feedback-jsonl requires an argument");
                }
                options.feedback_jsonl = argv[i];
            } else if (arg == "--feedback-channels") {
                if (++i >= argc) {
                    throw std::runtime_error("--feedback-channels requires an argument");
                }
                options.feedback_channels = argv[i];
            } else if (arg == "--campaign") {
                if (++i >= argc) {
                    throw std::runtime_error("--campaign requires an argument");
                }
                options.campaign = argv[i];
            } else if (arg == "--subject") {
                if (++i >= argc) {
                    throw std::runtime_error("--subject requires an argument");
                }
                options.subject = argv[i];
            } else if (arg == "--fuzzer-name") {
                if (++i >= argc) {
                    throw std::runtime_error("--fuzzer-name requires an argument");
                }
                options.fuzzer_name = argv[i];
            } else if (arg == "--mode") {
                if (++i >= argc) {
                    throw std::runtime_error("--mode requires an argument");
                }
                options.mode = argv[i];
            } else if (arg == "--run-id") {
                if (++i >= argc) {
                    throw std::runtime_error("--run-id requires an argument");
                }
                options.run_id = argv[i];
            } else if (arg == "--property-set-id") {
                if (++i >= argc) {
                    throw std::runtime_error("--property-set-id requires an argument");
                }
                options.property_set_id = argv[i];
            } else if (arg == "--monitor-backend") {
                if (++i >= argc) {
                    throw std::runtime_error("--monitor-backend requires an argument");
                }
                options.backend = mightypplcpp::parse_monitor_backend(argv[i]);
            } else if (arg == "--sat-inf") {
                set_sat_semantics(options, mightypplcpp::SatisfiabilitySemantics::Infinite);
            } else if (arg == "--sat-fin") {
                set_sat_semantics(options, mightypplcpp::SatisfiabilitySemantics::Finite);
            } else if (arg == "--skip-sat-precheck") {
                options.skip_sat_precheck = true;
            } else if (arg == "--ignore-unknown-propositions") {
                options.ignore_unknown_propositions = true;
            } else if (arg == "--near-deadline-ms") {
                if (++i >= argc) {
                    throw std::runtime_error("--near-deadline-ms requires an argument");
                }
                options.near_deadline_threshold_ms = static_cast<std::uint32_t>(std::stoul(argv[i]));
            } else if (arg == "--exact-slack-frontier-limit") {
                if (++i >= argc) {
                    throw std::runtime_error("--exact-slack-frontier-limit requires an argument");
                }
                options.exact_slack_frontier_limit = static_cast<std::size_t>(std::stoul(argv[i]));
            } else if (arg == "--no-concrete-slack") {
                options.disable_concrete_slack = true;
            } else if (arg == "--log-internal-anchor") {
                options.log_internal_anchor = true;
            } else if (arg == "--verbose") {
                options.verbose = true;
            } else if (!arg.empty() && arg[0] == '-') {
                throw std::runtime_error("unknown option: " + arg);
            } else if (options.formula_file.empty()) {
                options.formula_file = arg;
            } else {
                throw std::runtime_error("unexpected positional argument: " + arg);
            }
        }

        if (!options.help && options.formula.empty() == options.formula_file.empty()) {
            throw std::runtime_error("provide exactly one formula source: --formula or a formula file");
        }

        return options;
    }

    std::string read_formula_file(const std::string& path) {
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("could not open formula file: " + path);
        }

        std::stringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

} // namespace

int main(int argc, const char** argv) {
    try {
        const CliOptions cli = parse_args(argc, argv);
        if (cli.help) {
            print_usage(std::cout);
            return 0;
        }

        const std::string formula = cli.formula.empty()
                ? read_formula_file(cli.formula_file)
                : cli.formula;

        mightypplcpp::CompileOptions compile_options;
        compile_options.infinite = true;
        compile_options.verbose = cli.verbose;

        mightypplcpp::CompileOptions sat_options = compile_options;
        sat_options.infinite = cli.sat_semantics == mightypplcpp::SatisfiabilitySemantics::Infinite;
        sat_options.simplify = false;

        if (!cli.skip_sat_precheck) {
            const auto satisfiable = [&]() {
                if (cli.backend == mightypplcpp::MonitorBackend::NativeBdd) {
                    const auto sat_positive =
                            mightypplcpp::compile_positive_bdd_monitor_automaton_from_formula(formula, sat_options);
                    return mightypplcpp::is_satisfiable(sat_positive.automaton, cli.sat_semantics);
                }
                const auto sat_positive =
                        mightypplcpp::compile_positive_monitor_automaton_from_formula(formula, sat_options);
                return mightypplcpp::is_satisfiable(sat_positive.automaton, cli.sat_semantics);
            }();
            if (!satisfiable) {
                std::cerr << "UNSATISFIABLE (by " << sat_semantics_description(cli.sat_semantics) << ")\n";
                return 2;
            }
        }

        mightypplcpp::FeedbackSettings feedback_settings;
        feedback_settings.campaign = cli.campaign;
        feedback_settings.subject = cli.subject;
        feedback_settings.fuzzer_name = cli.fuzzer_name;
        feedback_settings.mode = cli.mode;
        feedback_settings.run_id = cli.run_id;
        feedback_settings.property_set_id = cli.property_set_id;
        feedback_settings.enabled_channels = mightypplcpp::parse_feedback_channels_csv(cli.feedback_channels);
        feedback_settings.near_deadline_threshold_ms = cli.near_deadline_threshold_ms;
        feedback_settings.exact_slack_frontier_limit = cli.exact_slack_frontier_limit;
        feedback_settings.enable_concrete_slack = !cli.disable_concrete_slack;
        feedback_settings.log_internal_anchor = cli.log_internal_anchor;
        feedback_settings.ignore_unknown_propositions = cli.ignore_unknown_propositions;
        mightypplcpp::MonitorSession session =
                mightypplcpp::MonitorSession::from_formula(formula, compile_options, feedback_settings, cli.backend);

        std::unique_ptr<mightypplcpp::IEventSource> source;
        std::ifstream file_input;
        if (!cli.input_file.empty()) {
            file_input.open(cli.input_file);
            if (!file_input) {
                throw std::runtime_error("could not open input file: " + cli.input_file);
            }
            source = std::make_unique<mightypplcpp::FileEventSource>(file_input, cli.input_file);
        } else {
            source = std::make_unique<mightypplcpp::StdinEventSource>(std::cin, &std::cerr);
        }

        std::ofstream feedback_output;
        std::unique_ptr<mightypplcpp::FeedbackJsonlLogger> feedback_logger;
        if (!cli.feedback_jsonl.empty()) {
            feedback_output.open(cli.feedback_jsonl);
            if (!feedback_output) {
                throw std::runtime_error("could not open feedback JSONL output: " + cli.feedback_jsonl);
            }
            feedback_logger = std::make_unique<mightypplcpp::FeedbackJsonlLogger>(feedback_output);
        }

        bool have_previous_timestamp = false;
        std::uint64_t previous_timestamp_ms = 0;
        std::uint64_t events_seen = 0;
        while (auto event = source->next()) {
            mightypplcpp::TimedTraceEvent trace_event;
            trace_event.event_index = events_seen;
            trace_event.timestamp_ms = event->time.second;
            trace_event.direction = "unknown";
            trace_event.session_phase = "unknown";
            trace_event.raw = *event;
            if (have_previous_timestamp) {
                trace_event.gap_prev_ms =
                        static_cast<std::int64_t>(trace_event.timestamp_ms) -
                        static_cast<std::int64_t>(previous_timestamp_ms);
            }

            const auto frame = session.step(trace_event);
            std::cout << frame.verdict << '\n';
            if (feedback_logger) {
                feedback_logger->write_event_feedback(session, trace_event, frame);
            }

            previous_timestamp_ms = trace_event.timestamp_ms;
            have_previous_timestamp = true;
            ++events_seen;
        }

        if (feedback_logger) {
            feedback_logger->write_run_outcome(session, events_seen, previous_timestamp_ms, session.verdict());
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "mitppl-monitor: " << e.what() << '\n';
        print_usage(std::cerr);
        return 1;
    }
}
