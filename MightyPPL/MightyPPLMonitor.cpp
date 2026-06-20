#include "MightyPPLMonitor.h"

#include "BddFixpoint.h"
#include "BddRuntimeMonitor.h"
#include "MightyPPL.h"

#include "antlr4-runtime.h"
#include "bdd.h"
#include "Fixpoint.h"
#include "state.h"

#include <algorithm>
#include <any>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace mightypplcpp {

    namespace {

        constexpr std::uint64_t kFNVOffset = 1469598103934665603ULL;
        constexpr std::uint64_t kFNVPrime = 1099511628211ULL;
        constexpr FeedbackChannelMask kVerdictOnlyChannelMaskSentinel = 1u << 31;
        bool g_bdd_runtime_manager_initialized = false;

        struct SlackSummary {
            std::int64_t min_slack_ms = -1;
            bool exact = false;
            std::uint32_t violated_count = 0;
            std::uint32_t near_deadline_count = 0;
            std::string critical_source;
        };

        std::string trim(const std::string& input) {
            auto begin = input.begin();
            while (begin != input.end() && std::isspace(static_cast<unsigned char>(*begin))) {
                ++begin;
            }

            auto end = input.end();
            while (end != begin && std::isspace(static_cast<unsigned char>(*(end - 1)))) {
                --end;
            }

            return std::string(begin, end);
        }

        std::string to_lower_copy(const std::string& value) {
            std::string lowered = value;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return lowered;
        }

        [[noreturn]] void event_error(const std::string& source, size_t line, const std::string& message) {
            throw std::runtime_error(source + ":" + std::to_string(line) + ": " + message);
        }

        uint32_t parse_uint(const std::string& text, size_t& pos, const std::string& source, size_t line) {
            const size_t begin = pos;
            while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
                ++pos;
            }
            if (begin == pos) {
                event_error(source, line, "expected an integer time bound");
            }

            return static_cast<uint32_t>(std::stoul(text.substr(begin, pos - begin)));
        }

        RawTimedEvent parse_raw_event_line(const std::string& line_text, const std::string& source, size_t line) {
            const std::string text = trim(line_text);
            size_t pos = 0;

            if (text.empty()) {
                event_error(source, line, "empty event");
            }
            if (text[pos] != '@') {
                event_error(source, line, "expected '@' at the beginning of an event");
            }
            ++pos;

            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                ++pos;
            }

            monitaal::interval_t time;
            if (pos < text.size() && text[pos] == '[') {
                ++pos;
                const auto lower = parse_uint(text, pos, source, line);
                while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                    ++pos;
                }
                if (pos >= text.size() || text[pos] != ',') {
                    event_error(source, line, "expected ',' in interval time");
                }
                ++pos;
                while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                    ++pos;
                }
                const auto upper = parse_uint(text, pos, source, line);
                while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                    ++pos;
                }
                if (pos >= text.size() || text[pos] != ']') {
                    event_error(source, line, "expected ']' after interval time");
                }
                ++pos;
                if (upper < lower) {
                    event_error(source, line, "interval upper bound is smaller than lower bound");
                }
                time = {lower, upper};
            } else {
                const auto point = parse_uint(text, pos, source, line);
                time = {point, point};
            }

            const std::string propositions = trim(text.substr(pos));
            if (propositions.empty()) {
                event_error(source, line, "expected proposition set after time; use '-' for empty set");
            }

            return RawTimedEvent{time, propositions, source, line};
        }

        void reset_build_state(const CompileOptions& options) {
            gcd = 0;
            last_intersection = false;
            num_all_props = 0;
            components_counter = 0;
            single = false;
            props_to_keep.clear();
            sat_paths.clear();
            monitor_alphabet.clear();

            spec_file = nullptr;
            out_file = nullptr;
            out_format = std::nullopt;
            out_flatten = true;
            comp_flatten = false;
            out_fin = !options.infinite;
            debug = options.debug;
            back = options.simplify;
            monitor_concrete_labels = true;

            varphi = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
            div = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
            temporal_components.clear();
            model = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
        }

        void clear_bdd_build_state() {
            varphi = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
            div = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
            temporal_components.clear();
            model = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
            props_to_keep.clear();
            sat_paths.clear();
            monitor_alphabet.clear();
        }

        void ensure_bdd_runtime_manager() {
            if (!g_bdd_runtime_manager_initialized) {
                bdd_init(1000, 100);
                g_bdd_runtime_manager_initialized = true;
            }
        }

        void shutdown_bdd_runtime_manager_if_needed() {
            if (g_bdd_runtime_manager_initialized) {
                bdd_done();
                g_bdd_runtime_manager_initialized = false;
            }
        }

        void ensure_bdd_runtime_varnum(int max_var_index) {
            ensure_bdd_runtime_manager();
            if (bdd_varnum() <= max_var_index) {
                bdd_setvarnum(max_var_index + 1);
            }
        }

        std::map<std::string, int> extract_proposition_indices(const std::string& formula) {
            antlr4::ANTLRInputStream input(formula);
            MitlLexer lexer(&input);
            antlr4::CommonTokenStream tokens(&lexer);
            MitlParser parser(&tokens);
            MitlParser::MainContext* parsed = parser.main();
            if (parser.getNumberOfSyntaxErrors() > 0) {
                throw std::runtime_error("failed to parse MITL/MITPPL formula");
            }

            MitlTypingVisitor typing_visitor;
            typing_visitor.visitMain(parsed);

            MitlToNNFVisitor to_nnf_visitor;
            const auto nnf = std::any_cast<std::string>(to_nnf_visitor.visitMain(parsed));

            antlr4::ANTLRInputStream nnf_input(nnf);
            MitlLexer nnf_lexer(&nnf_input);
            antlr4::CommonTokenStream nnf_tokens(&nnf_lexer);
            MitlParser nnf_parser(&nnf_tokens);
            MitlParser::MainContext* nnf_formula = nnf_parser.main();
            if (nnf_parser.getNumberOfSyntaxErrors() > 0) {
                throw std::runtime_error("failed to parse formula rewritten into NNF");
            }

            typing_visitor.visitMain(nnf_formula);
            MitlAtomNumberingVisitor temporal_numbering_visitor;
            temporal_numbering_visitor.visitMain(nnf_formula);
            return nnf_formula->props;
        }

        std::vector<std::string> ordered_monitor_alphabet(const std::map<std::string, int>& propositions) {
            std::vector<std::pair<std::string, int>> ordered(propositions.begin(), propositions.end());
            std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
                return lhs.second < rhs.second;
            });

            std::vector<std::string> alphabet;
            alphabet.reserve(ordered.size());
            for (const auto& [name, _] : ordered) {
                alphabet.push_back(name);
            }
            return alphabet;
        }

        bdd concrete_label_to_bdd(const std::string& label,
                                  const std::vector<std::string>& alphabet,
                                  const std::map<std::string, int>& propositions) {
            if (label != "-" && label.size() != alphabet.size()) {
                throw std::runtime_error("concrete monitor label length does not match monitor alphabet");
            }

            int max_var_index = 0;
            for (const auto& [_, index] : propositions) {
                max_var_index = std::max(max_var_index, index);
            }
            ensure_bdd_runtime_varnum(max_var_index);

            bdd label_bdd = bddtrue;
            for (std::size_t i = 0; i < alphabet.size(); ++i) {
                const auto found = propositions.find(alphabet[i]);
                if (found == propositions.end()) {
                    throw std::runtime_error("missing proposition index while lifting concrete monitor automaton");
                }

                const bool present = label != "-" && label[i] == '1';
                label_bdd &= present ? bdd_ithvar(found->second) : !bdd_ithvar(found->second);
            }
            return label_bdd;
        }

        monitaal::TAwithBDDEdges lift_concrete_monitor_automaton_to_bdd(const monitaal::TA& automaton,
                                                                        const std::vector<std::string>& alphabet,
                                                                        const std::map<std::string, int>& propositions) {
            monitaal::bdd_edges_t bdd_edges;
            for (const auto& [location_id, _] : automaton.locations()) {
                for (const auto& edge : automaton.edges_from(location_id)) {
                    bdd_edges.emplace_back(edge.from(),
                                           edge.to(),
                                           edge.guard(),
                                           edge.reset(),
                                           concrete_label_to_bdd(edge.label(), alphabet, propositions));
                }
            }

            monitaal::clock_map_t clocks;
            for (monitaal::clock_index_t i = 0; i < automaton.number_of_clocks(); ++i) {
                clocks.insert({i, automaton.clock_name(i)});
            }

            monitaal::locations_t locations;
            for (const auto& [_, location] : automaton.locations()) {
                locations.push_back(location);
            }

            return monitaal::TAwithBDDEdges(automaton.name(),
                                            clocks,
                                            locations,
                                            bdd_edges,
                                            automaton.initial_location());
        }

        monitaal::TA compile_one_formula(const std::string& formula, const CompileOptions& options) {
            reset_build_state(options);

            antlr4::ANTLRInputStream input(formula);
            MitlLexer lexer(&input);
            antlr4::CommonTokenStream tokens(&lexer);
            MitlParser parser(&tokens);
            MitlParser::MainContext* parsed = parser.main();
            if (parser.getNumberOfSyntaxErrors() > 0) {
                throw std::runtime_error("failed to parse MITL/MITPPL formula");
            }

            auto [ta, _] = build_ta_from_main(parsed);
            return ta;
        }

        monitaal::TAwithBDDEdges compile_one_formula_bdd(const std::string& formula,
                                                         const CompileOptions& options,
                                                         const std::map<std::string, int>& propositions) {
            reset_build_state(options);
            // Reuse the monitor-time "preserve original bounds" behavior from the
            // concrete backend while still returning a native BDD projection below.
            monitor_concrete_labels = true;

            antlr4::ANTLRInputStream input(formula);
            MitlLexer lexer(&input);
            antlr4::CommonTokenStream tokens(&lexer);
            MitlParser parser(&tokens);
            MitlParser::MainContext* parsed = parser.main();
            if (parser.getNumberOfSyntaxErrors() > 0) {
                throw std::runtime_error("failed to parse MITL/MITPPL formula");
            }

            auto [_ignored, __] = build_ta_from_main(parsed);
            monitor_concrete_labels = false;

            std::vector<monitaal::TAwithBDDEdges> automata = temporal_components;
            automata.insert(automata.begin(), div);
            automata.insert(automata.begin(), varphi);
            automata.insert(automata.end(), model);

            monitaal::TAwithBDDEdges product = monitaal::TAwithBDDEdges::intersection(automata);

            std::set<int> props_to_remove;
            std::set<int> prop_ids;
            props_to_remove.insert(0);
            for (const auto& [_, id] : propositions) {
                prop_ids.insert(id);
            }
            for (auto i = 0; i < num_all_props; ++i) {
                if (!prop_ids.count(i + 1)) {
                    props_to_remove.insert(i + 1);
                }
            }

            return product.projection_bdd(props_to_remove);
        }

        class ScopedCoutRedirect {
        public:
            explicit ScopedCoutRedirect(bool verbose) : _old(std::cout.rdbuf()) {
                if (verbose) {
                    std::cout.rdbuf(std::cerr.rdbuf());
                } else {
                    std::cout.rdbuf(_sink.rdbuf());
                }
            }

            ~ScopedCoutRedirect() {
                std::cout.rdbuf(_old);
            }

        private:
            std::streambuf* _old;
            std::ostringstream _sink;
        };

        void hash_combine_u64(std::uint64_t& seed, std::uint64_t value) {
            seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
        }

        std::uint64_t stable_hash(const std::string& text) {
            std::uint64_t hash = kFNVOffset;
            for (unsigned char c : text) {
                hash ^= static_cast<std::uint64_t>(c);
                hash *= kFNVPrime;
            }
            return hash;
        }

        std::string json_escape(const std::string& text) {
            std::ostringstream out;
            for (unsigned char c : text) {
                switch (c) {
                    case '\"': out << "\\\""; break;
                    case '\\': out << "\\\\"; break;
                    case '\b': out << "\\b"; break;
                    case '\f': out << "\\f"; break;
                    case '\n': out << "\\n"; break;
                    case '\r': out << "\\r"; break;
                    case '\t': out << "\\t"; break;
                    default:
                        if (c < 0x20) {
                            out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c)
                                << std::dec << std::setfill(' ');
                        } else {
                            out << static_cast<char>(c);
                        }
                        break;
                }
            }
            return out.str();
        }

        std::string quote_json(const std::string& text) {
            return "\"" + json_escape(text) + "\"";
        }

        template<typename T>
        std::string number_or_null_json(const std::optional<T>& value) {
            if (!value.has_value()) {
                return "null";
            }
            return std::to_string(*value);
        }

        std::string string_array_json(const std::vector<std::string>& values) {
            std::ostringstream out;
            out << "[";
            for (size_t i = 0; i < values.size(); ++i) {
                if (i > 0) {
                    out << ",";
                }
                out << quote_json(values[i]);
            }
            out << "]";
            return out.str();
        }

        std::vector<std::string> split_csv(const std::string& value) {
            std::vector<std::string> parts;
            size_t begin = 0;
            while (begin <= value.size()) {
                size_t end = value.find(',', begin);
                if (end == std::string::npos) {
                    end = value.size();
                }
                const std::string token = trim(value.substr(begin, end - begin));
                if (!token.empty()) {
                    parts.push_back(token);
                }
                if (end == value.size()) {
                    break;
                }
                begin = end + 1;
            }
            return parts;
        }

        bool is_unknown_class(const std::string& value) {
            return value.empty() || to_lower_copy(value) == "unknown";
        }

        bool is_ordinal_retransmission_label(const std::string& value) {
            if (value.size() <= 3 || value.rfind("rtx", 0) != 0) {
                return false;
            }
            return std::all_of(value.begin() + 3, value.end(), [](unsigned char ch) {
                return std::isdigit(ch) != 0;
            });
        }

        bool is_ssh_authenticated_phase(const TimedTraceEvent& event) {
            return event.session_phase == "authenticated";
        }

        bool is_ssh_post_auth_request_class(const std::string& request_class) {
            return request_class == "global_request" ||
                   request_class == "channel_open" ||
                   request_class == "channel_open_confirmation" ||
                   request_class == "channel_data" ||
                   request_class == "channel_eof" ||
                   request_class == "channel_close";
        }

        bool is_ssh_keepalive_request_class(const std::string& request_class) {
            return request_class == "ignore" || request_class == "global_request";
        }

        bool is_terminal_request_class(const std::string& request_class) {
            return request_class == "quit" ||
                   request_class == "teardown" ||
                   request_class == "bye" ||
                   request_class == "exit" ||
                   request_class == "logout" ||
                   request_class == "stop" ||
                   request_class == "disconnect" ||
                   request_class == "release_rq" ||
                   request_class == "release_rp" ||
                   request_class == "abort";
        }

        void populate_trace_semantics_from_raw(TimedTraceEvent& event) {
            const std::string trimmed = trim(event.raw.propositions);
            if (trimmed.empty()) {
                if (event.parser_state_id == 0) {
                    event.parser_state_id = stable_hash("empty");
                }
                return;
            }

            if (trimmed == "-") {
                event.direction = "silence";
                event.request_class = "silence";
                if (event.session_phase.empty() || event.session_phase == "unknown") {
                    event.session_phase = "idle";
                }
                if (event.parser_state_id == 0) {
                    event.parser_state_id = stable_hash("silence");
                }
                return;
            }

            const auto tokens = split_csv(trimmed);
            std::string tx_token;
            bool saw_request = false;
            bool saw_response = false;

            for (const auto& token : tokens) {
                const auto lowered = to_lower_copy(token);
                if (lowered == "req") {
                    saw_request = true;
                    continue;
                }
                if (lowered == "rsp") {
                    saw_response = true;
                    continue;
                }
                if (lowered == "silence") {
                    event.direction = "silence";
                    event.request_class = "silence";
                    if (event.session_phase.empty() || event.session_phase == "unknown") {
                        event.session_phase = "idle";
                    }
                    continue;
                }
                if (lowered.rfind("req_", 0) == 0 && is_unknown_class(event.request_class)) {
                    event.request_class = lowered.substr(4);
                    continue;
                }
                if (lowered.rfind("rsp_", 0) == 0 && is_unknown_class(event.response_class)) {
                    event.response_class = lowered.substr(4);
                    continue;
                }
                if (lowered.rfind("state_", 0) == 0 && is_unknown_class(event.response_class)) {
                    event.response_class = lowered.substr(6);
                    continue;
                }
                if (lowered.rfind("phase_", 0) == 0 &&
                    (event.session_phase.empty() || event.session_phase == "unknown")) {
                    event.session_phase = lowered.substr(6);
                    continue;
                }
                if (lowered.rfind("sip_tx_", 0) == 0 && tx_token.empty()) {
                    tx_token = lowered;
                    continue;
                }
                if (lowered == "invite" &&
                    (is_unknown_class(event.request_class) || event.request_class == "invite")) {
                    event.request_class = "invite";
                    continue;
                }
                if (lowered == "ch") {
                    event.request_class = "ch";
                    continue;
                }
                if (lowered == "assoc_req") {
                    event.request_class = "assoc_req";
                    continue;
                }
                if (is_ordinal_retransmission_label(lowered)) {
                    event.request_class = lowered;
                    continue;
                }
                if (lowered == "rtx") {
                    if (is_unknown_class(event.request_class) ||
                        event.request_class == "invite" ||
                        event.request_class == "ch") {
                        event.request_class = "rtx";
                    }
                    continue;
                }
                if (lowered == "session_activity") {
                    event.request_class = "session_activity";
                    continue;
                }
                if (lowered == "conn_open") {
                    event.request_class = "conn_open";
                    continue;
                }
                if (lowered == "invite_rsp" && is_unknown_class(event.response_class)) {
                    event.response_class = "invite_rsp";
                    continue;
                }
                if (lowered == "session_open" &&
                    (is_unknown_class(event.response_class) || event.response_class == "200")) {
                    event.response_class = "session_open";
                    continue;
                }
                if (lowered == "acse_rsp" &&
                    (is_unknown_class(event.response_class) || event.response_class == "associate_ac" ||
                     event.response_class == "associate_rj")) {
                    event.response_class = "acse_rsp";
                    continue;
                }
                if (lowered == "auth_done" &&
                    (is_unknown_class(event.response_class) || event.response_class == "userauth_success" ||
                     event.response_class == "disconnect")) {
                    event.response_class = "auth_done";
                    continue;
                }
            }

            if (event.direction.empty() || event.direction == "unknown" || event.direction == "input") {
                if (saw_request && !saw_response) {
                    event.direction = "request";
                } else if (saw_response && !saw_request) {
                    event.direction = "response";
                } else if (saw_request || saw_response) {
                    event.direction = "request+response";
                }
            }

            if ((event.session_phase.empty() || event.session_phase == "unknown") &&
                !is_unknown_class(event.request_class)) {
                if (event.request_class == "invite") {
                    event.session_phase = "calling";
                } else if (event.request_class == "ch") {
                    event.session_phase = "handshake";
                } else if (event.request_class == "assoc_req") {
                    event.session_phase = "association";
                } else if (event.request_class == "rtx" ||
                           is_ordinal_retransmission_label(event.request_class)) {
                    event.session_phase = "retransmit";
                } else if (event.request_class == "session_activity") {
                    event.session_phase = "session";
                } else if (event.request_class == "conn_open") {
                    event.session_phase = "preauth";
                }
            }
            if ((event.session_phase.empty() || event.session_phase == "unknown") &&
                !is_unknown_class(event.response_class) &&
                !event.response_class.empty()) {
                if (event.response_class == "acse_rsp") {
                    event.session_phase = "association";
                } else if (event.response_class == "session_open") {
                    event.session_phase = "session";
                } else if (event.response_class == "auth_done") {
                    event.session_phase = "authenticated";
                }
                if (std::isdigit(static_cast<unsigned char>(event.response_class.front()))) {
                    if (event.response_class.front() == '1') {
                        event.session_phase = "proceeding";
                    } else {
                        event.session_phase = "completed";
                    }
                }
            }

            if (event.candidate_next_event_classes.empty()) {
                if (!is_unknown_class(event.request_class) && event.request_class != "silence") {
                    event.candidate_next_event_classes.push_back(event.request_class);
                }
                if (!is_unknown_class(event.response_class) && event.response_class != event.request_class) {
                    event.candidate_next_event_classes.push_back(event.response_class);
                }
            }

            if (event.parser_state_id == 0) {
                std::uint64_t hash = tx_token.empty() ? stable_hash(trimmed) : stable_hash(tx_token);
                hash_combine_u64(hash, stable_hash(event.request_class));
                hash_combine_u64(hash, stable_hash(event.response_class));
                hash_combine_u64(hash, stable_hash(event.session_phase));
                event.parser_state_id = hash;
            }
        }

        std::string clock_ref(const monitaal::TA& automaton, monitaal::clock_index_t index) {
            if (index == 0) {
                return "0";
            }
            return automaton.clock_name(index);
        }

        std::string constraint_to_string(const monitaal::constraint_t& constraint, const monitaal::TA& automaton) {
            std::ostringstream out;
            out << clock_ref(automaton, constraint._i) << " - " << clock_ref(automaton, constraint._j)
                << (constraint._bound.is_strict() ? " < " : " <= ");
            if (constraint._bound.is_inf()) {
                out << "inf";
            } else {
                out << constraint._bound.get_bound();
            }
            return out.str();
        }

        std::string constraints_to_string(const monitaal::constraints_t& constraints, const monitaal::TA& automaton) {
            if (constraints.empty()) {
                return "";
            }
            std::ostringstream out;
            for (size_t i = 0; i < constraints.size(); ++i) {
                if (i > 0) {
                    out << " && ";
                }
                out << constraint_to_string(constraints[i], automaton);
            }
            return out.str();
        }

        std::uint64_t infer_obligation_phase_mask(const std::string& location_name) {
            const std::string lowered = to_lower_copy(location_name);
            std::uint64_t mask = 0;
            if (lowered.find("seq_in") != std::string::npos) {
                mask |= 1ULL << 0;
            }
            if (lowered.find("seq_out") != std::string::npos) {
                mask |= 1ULL << 1;
            }
            if (lowered.find("accept") != std::string::npos) {
                mask |= 1ULL << 2;
            }
            if (lowered.find("wait") != std::string::npos) {
                mask |= 1ULL << 3;
            }
            if (lowered.find("sink") != std::string::npos || lowered.find("dead") != std::string::npos) {
                mask |= 1ULL << 4;
            }
            if (mask == 0) {
                mask = 1ULL << 5;
            }
            return mask;
        }

        std::string infer_timer_class(const monitaal::constraints_t& constraints) {
            bool has_upper = false;
            bool has_lower = false;
            for (const auto& constraint : constraints) {
                if (constraint._bound.is_inf()) {
                    continue;
                }
                if (constraint._j == 0) {
                    has_upper = true;
                } else if (constraint._i == 0) {
                    has_lower = true;
                } else {
                    has_upper = true;
                    has_lower = true;
                }
            }
            if (has_upper && has_lower) {
                return "window";
            }
            if (has_upper) {
                return "deadline";
            }
            if (has_lower) {
                return "delay";
            }
            return constraints.empty() ? "untimed" : "generic";
        }

        std::unordered_map<monitaal::location_id_t, LocationMetadata>
        build_location_metadata_map(const monitaal::TA& automaton) {
            std::unordered_map<monitaal::location_id_t, LocationMetadata> metadata;
            for (const auto& [location_id, location] : automaton.locations()) {
                LocationMetadata entry;
                entry.location_id = location_id;
                entry.location_name = location.name();
                entry.accepting = location.is_accept();
                entry.invariant_text = constraints_to_string(location.invariant(), automaton);
                entry.source_subformula = location.name();
                entry.obligation_phase_mask = infer_obligation_phase_mask(location.name());
                entry.timer_class = infer_timer_class(location.invariant());
                entry.protocol_semantic_anchor = location.name();
                metadata.emplace(location_id, std::move(entry));
            }
            return metadata;
        }

        std::string state_signature_item(const monitaal::symbolic_state_t& state) {
            std::ostringstream item;
            item << state.location() << ":" << state.federation();
            return item.str();
        }

        std::string state_signature_item(const monitaal::concrete_state_t& state) {
            std::ostringstream item;
            item << state.location() << ":";
            const auto valuation = state.valuation();
            for (size_t i = 0; i < valuation.size(); ++i) {
                if (i > 0) {
                    item << ",";
                }
                item << valuation[i];
            }
            return item.str();
        }

        template<class StateT>
        std::string frontier_signature_string(const std::vector<StateT>& frontier) {
            std::vector<std::string> parts;
            parts.reserve(frontier.size());
            for (const auto& state : frontier) {
                parts.push_back(state_signature_item(state));
            }
            std::sort(parts.begin(), parts.end());

            std::ostringstream out;
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i > 0) {
                    out << "|";
                }
                out << parts[i];
            }
            return out.str();
        }

        template<class StateT>
        std::uint64_t frontier_signature_hash(const std::vector<StateT>& frontier) {
            return stable_hash(frontier_signature_string(frontier));
        }

        std::string symbolic_zone_signature_item(const monitaal::symbolic_state_t& state) {
            std::ostringstream item;
            item << "loc=" << state.location() << ";empty=" << state.is_empty() << ";fed=[";
            bool first_dbm = true;
            for (const auto& dbm : state.federation()) {
                if (first_dbm) {
                    first_dbm = false;
                } else {
                    item << "|";
                }
                item << "dim=" << dbm.dimension() << ":";
                bool first_bound = true;
                for (pardibaal::dim_t i = 0; i < dbm.dimension(); ++i) {
                    for (pardibaal::dim_t j = 0; j < dbm.dimension(); ++j) {
                        if (first_bound) {
                            first_bound = false;
                        } else {
                            item << ",";
                        }
                        const auto bound = dbm.at(i, j);
                        item << i << "-" << j;
                        if (bound.is_inf()) {
                            item << "inf";
                        } else {
                            item << (bound.is_strict() ? "<" : "<=") << bound.get_bound();
                        }
                    }
                }
            }
            item << "]";
            return item.str();
        }

        std::string concrete_point_zone_signature_item(const monitaal::concrete_state_t& state) {
            std::ostringstream item;
            item << "loc=" << state.location() << ";empty=" << state.is_empty() << ";point-dbm=[";
            const auto valuation = state.valuation();
            bool first_bound = true;
            for (size_t i = 0; i < valuation.size(); ++i) {
                for (size_t j = 0; j < valuation.size(); ++j) {
                    if (first_bound) {
                        first_bound = false;
                    } else {
                        item << ",";
                    }
                    const auto diff = static_cast<std::int64_t>(valuation[i]) -
                                      static_cast<std::int64_t>(valuation[j]);
                    item << i << "-" << j << "<=" << diff;
                }
            }
            item << "]";
            return item.str();
        }

        std::string symbolic_zone_signature_string(const std::vector<monitaal::symbolic_state_t>& states) {
            std::vector<std::string> parts;
            parts.reserve(states.size());
            for (const auto& state : states) {
                parts.push_back(symbolic_zone_signature_item(state));
            }
            std::sort(parts.begin(), parts.end());

            std::ostringstream out;
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i > 0) {
                    out << "|";
                }
                out << parts[i];
            }
            return out.str();
        }

        std::string concrete_point_zone_signature_string(const std::vector<monitaal::concrete_state_t>& states) {
            std::vector<std::string> parts;
            parts.reserve(states.size());
            for (const auto& state : states) {
                parts.push_back(concrete_point_zone_signature_item(state));
            }
            std::sort(parts.begin(), parts.end());

            std::ostringstream out;
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i > 0) {
                    out << "|";
                }
                out << parts[i];
            }
            return out.str();
        }

        std::uint64_t timed_zone_hash(const std::vector<monitaal::symbolic_state_t>& positive_symbolic,
                                      const std::vector<monitaal::symbolic_state_t>& negative_symbolic,
                                      const std::vector<monitaal::concrete_state_t>& positive_concrete,
                                      const std::vector<monitaal::concrete_state_t>& negative_concrete,
                                      const SlackSummary& slack_summary,
                                      bool concrete_exact) {
            std::ostringstream signature;
            if (concrete_exact) {
                // A concrete monitor valuation denotes a point-zone; encode it as
                // the canonical pairwise difference matrix so the hash is timing-sensitive.
                signature << "source=concrete-point-dbm";
                signature << ";pos=" << concrete_point_zone_signature_string(positive_concrete);
                signature << ";neg=" << concrete_point_zone_signature_string(negative_concrete);
            } else {
                signature << "source=symbolic-federation";
                signature << ";pos=" << symbolic_zone_signature_string(positive_symbolic);
                signature << ";neg=" << symbolic_zone_signature_string(negative_symbolic);
            }
            signature << ";min_slack=" << slack_summary.min_slack_ms
                      << ";violated=" << slack_summary.violated_count
                      << ";near_deadline=" << slack_summary.near_deadline_count
                      << ";exact=" << (slack_summary.exact ? "1" : "0");
            return stable_hash(signature.str());
        }

        std::vector<std::string> derive_candidate_classes(const TimedTraceEvent& event) {
            std::vector<std::string> candidates;
            auto add_candidate = [&candidates](const std::string& raw) {
                const std::string lowered = to_lower_copy(trim(raw));
                if (lowered.empty() || lowered == "-" || lowered == "unknown" || lowered == "req" ||
                    lowered == "rsp" || lowered == "silence") {
                    return;
                }
                if (std::find(candidates.begin(), candidates.end(), lowered) != candidates.end()) {
                    return;
                }
                candidates.push_back(lowered);
            };

            const std::string trimmed = trim(event.raw.propositions);
            if (!trimmed.empty() && trimmed != "-") {
                for (const auto& token : split_csv(trimmed)) {
                    const std::string lowered = to_lower_copy(token);
                    if (lowered.rfind("req_", 0) == 0 && lowered.size() > 4) {
                        add_candidate(lowered.substr(4));
                    }
                }
            }

            if (!event.candidate_next_event_classes.empty()) {
                for (const auto& candidate : event.candidate_next_event_classes) {
                    add_candidate(candidate);
                }
            }

            if (is_ssh_authenticated_phase(event)) {
                add_candidate("global_request");
                add_candidate("channel_open");
                add_candidate("ignore");
                if (event.request_class == "channel_open" ||
                    event.request_class == "channel_open_confirmation" ||
                    event.request_class == "channel_data") {
                    add_candidate("channel_data");
                    add_candidate("channel_eof");
                    add_candidate("channel_close");
                }
            }

            if (!is_unknown_class(event.request_class)) {
                add_candidate(event.request_class);
            }
            if (!is_unknown_class(event.response_class)) {
                add_candidate(event.response_class);
            }

            if (!trimmed.empty() && trimmed != "-") {
                for (const auto& token : split_csv(trimmed)) {
                    const std::string lowered = to_lower_copy(token);
                    if (lowered.rfind("proto_", 0) == 0 ||
                        lowered.rfind("req_", 0) == 0 ||
                        lowered.rfind("state_", 0) == 0 ||
                        lowered.rfind("phase_", 0) == 0 ||
                        lowered.rfind("sip_tx_", 0) == 0 ||
                        lowered.rfind("rtsp_sess_", 0) == 0 ||
                        lowered.rfind("rsp_", 0) == 0) {
                        continue;
                    }
                    add_candidate(lowered);
                }
            }

            return candidates;
        }

        bool derive_keepalive_hint(const TimedTraceEvent& event,
                                   const ProtocolSemanticFeedback& protocol_feedback,
                                   const ZoneFeedback& zone_feedback) {
            const bool boundary_sensitive =
                    zone_feedback.boundary_class == BoundaryClass::NearDeadline ||
                    zone_feedback.boundary_class == BoundaryClass::CrossedDeadline ||
                    zone_feedback.boundary_class == BoundaryClass::AmbiguityBand;
            if (!boundary_sensitive) {
                return false;
            }

            const auto& request_class = protocol_feedback.request_class;
            const auto& response_class = protocol_feedback.response_class;
            if (protocol_feedback.close_or_reset_seen ||
                is_terminal_request_class(request_class) ||
                response_class == "disconnect") {
                return false;
            }
            if (protocol_feedback.session_phase == "idle") {
                return true;
            }
            if (request_class == "session_activity" || response_class == "session_open") {
                return true;
            }
            if (request_class == "pdata_tf" || response_class == "acse_rsp") {
                return true;
            }
            if (request_class == "conn_open" || request_class == "kexinit") {
                return true;
            }
            if (protocol_feedback.session_phase == "authenticated" &&
                (response_class == "auth_done" ||
                 is_ssh_keepalive_request_class(request_class) ||
                 is_ssh_post_auth_request_class(request_class))) {
                return true;
            }
            if (request_class == "ch" || request_class == "clienthello") {
                return true;
            }
            return false;
        }

        bool derive_close_or_reset(const TimedTraceEvent& event) {
            if (event.close_or_reset_seen) {
                return true;
            }
            const auto lowered = to_lower_copy(event.raw.propositions);
            return lowered.find("close") != std::string::npos ||
                   lowered.find("disconnect") != std::string::npos ||
                   lowered.find("reset") != std::string::npos ||
                   lowered.find("timeout") != std::string::npos ||
                   lowered.find("teardown") != std::string::npos;
        }

        std::int64_t constraint_slack_ms(const monitaal::constraint_t& constraint,
                                         const monitaal::valuation_t& valuation) {
            if (constraint._bound.is_inf()) {
                return std::numeric_limits<std::int64_t>::max();
            }
            const std::int64_t lhs = static_cast<std::int64_t>(valuation.at(constraint._i))
                                     - static_cast<std::int64_t>(valuation.at(constraint._j));
            std::int64_t slack = static_cast<std::int64_t>(constraint._bound.get_bound()) - lhs;
            if (constraint._bound.is_strict()) {
                slack -= 1;
            }
            return slack;
        }

        void accumulate_constraints_slack(const monitaal::constraints_t& constraints,
                                          const monitaal::valuation_t& valuation,
                                          const monitaal::TA& automaton,
                                          const std::string& prefix,
                                          std::uint32_t near_deadline_threshold_ms,
                                          SlackSummary& summary) {
            for (const auto& constraint : constraints) {
                if (constraint._bound.is_inf()) {
                    continue;
                }
                const auto slack = constraint_slack_ms(constraint, valuation);
                if (summary.min_slack_ms < 0 || slack < summary.min_slack_ms) {
                    summary.min_slack_ms = slack;
                    summary.critical_source = prefix + constraint_to_string(constraint, automaton);
                }
                if (slack < 0) {
                    ++summary.violated_count;
                }
                if (slack >= 0 && slack <= static_cast<std::int64_t>(near_deadline_threshold_ms)) {
                    ++summary.near_deadline_count;
                }
            }
        }

        void accumulate_state_slack(const std::vector<monitaal::concrete_state_t>& states,
                                    const monitaal::TA& automaton,
                                    std::uint32_t near_deadline_threshold_ms,
                                    SlackSummary& summary) {
            for (const auto& state : states) {
                if (state.is_empty()) {
                    continue;
                }
                const auto valuation = state.valuation();
                const auto& location = automaton.locations().at(state.location());
                accumulate_constraints_slack(location.invariant(), valuation, automaton,
                                             location.name() + " invariant: ",
                                             near_deadline_threshold_ms, summary);
                for (const auto& edge : automaton.edges_from(state.location())) {
                    accumulate_constraints_slack(edge.guard(), valuation, automaton,
                                                 location.name() + " edge(" + edge.label() + "): ",
                                                 near_deadline_threshold_ms, summary);
                }
            }
        }

        BoundaryClass classify_boundary(const SlackSummary& slack_summary,
                                        std::size_t frontier_size_pos,
                                        std::size_t frontier_size_neg,
                                        std::uint32_t near_deadline_threshold_ms) {
            if (slack_summary.violated_count > 0) {
                return BoundaryClass::CrossedDeadline;
            }
            if (frontier_size_pos > 0 && frontier_size_neg > 0 &&
                slack_summary.min_slack_ms >= 0 &&
                slack_summary.min_slack_ms <= static_cast<std::int64_t>(near_deadline_threshold_ms)) {
                return BoundaryClass::AmbiguityBand;
            }
            if (slack_summary.min_slack_ms >= 0 &&
                slack_summary.min_slack_ms <= static_cast<std::int64_t>(near_deadline_threshold_ms)) {
                return BoundaryClass::NearDeadline;
            }
            if (frontier_size_pos > 0 || frontier_size_neg > 0) {
                return BoundaryClass::SafeInterior;
            }
            return BoundaryClass::Unknown;
        }

        int progress_bin_for(monitaal::monitor_answer_e verdict, BoundaryClass boundary_class) {
            if (verdict == monitaal::POSITIVE) {
                return 3;
            }
            if (verdict == monitaal::NEGATIVE) {
                return 4;
            }
            if (boundary_class == BoundaryClass::AmbiguityBand || boundary_class == BoundaryClass::NearDeadline) {
                return 2;
            }
            return 1;
        }

        std::uint64_t semantic_state_hash(const FrontierFeedback& frontier,
                                          const ZoneFeedback& zone,
                                          const ObligationFeedback& obligation,
                                          const ProtocolSemanticFeedback& semantic) {
            std::uint64_t hash = kFNVOffset;
            hash_combine_u64(hash, frontier.pos_frontier_hash);
            hash_combine_u64(hash, frontier.neg_frontier_hash);
            hash_combine_u64(hash, static_cast<std::uint64_t>(zone.boundary_class));
            hash_combine_u64(hash, obligation.obligation_phase_mask);
            hash_combine_u64(hash, stable_hash(semantic.session_phase));
            hash_combine_u64(hash, semantic.parser_state_id);
            return hash;
        }

        std::string feedback_vector_json(const FeedbackVector& vector) {
            std::ostringstream out;
            out << "{"
                << "\"frontier\":{"
                << "\"pos_frontier_hash\":" << vector.frontier.pos_frontier_hash << ","
                << "\"neg_frontier_hash\":" << vector.frontier.neg_frontier_hash << ","
                << "\"frontier_size_pos\":" << vector.frontier.frontier_size_pos << ","
                << "\"frontier_size_neg\":" << vector.frontier.frontier_size_neg << ","
                << "\"frontier_novelty\":" << (vector.frontier.frontier_novelty ? "true" : "false")
                << "},"
                << "\"zone\":{"
                << "\"zone_hash\":" << vector.zone.zone_hash << ","
                << "\"min_slack_ms\":" << vector.zone.min_slack_ms << ","
                << "\"slack_exact\":" << (vector.zone.slack_exact ? "true" : "false") << ","
                << "\"boundary_class\":" << quote_json(boundary_class_name(vector.zone.boundary_class)) << ","
                << "\"violated_guard_count\":" << vector.zone.violated_guard_count << ","
                << "\"near_deadline_count\":" << vector.zone.near_deadline_count
                << "},"
                << "\"obligation\":{"
                << "\"active_obligation_count\":" << vector.obligation.active_obligation_count << ","
                << "\"opened_now\":" << vector.obligation.opened_now << ","
                << "\"satisfied_now\":" << vector.obligation.satisfied_now << ","
                << "\"expired_now\":" << vector.obligation.expired_now << ","
                << "\"obligation_phase_mask\":" << vector.obligation.obligation_phase_mask
                << "},"
                << "\"property_progress\":{"
                << "\"property_progress_vector\":[";
            for (size_t i = 0; i < vector.property_progress.property_progress_vector.size(); ++i) {
                if (i > 0) {
                    out << ",";
                }
                out << vector.property_progress.property_progress_vector[i];
            }
            out << "],\"newly_reached_progress_bins\":[";
            for (size_t i = 0; i < vector.property_progress.newly_reached_progress_bins.size(); ++i) {
                if (i > 0) {
                    out << ",";
                }
                out << vector.property_progress.newly_reached_progress_bins[i];
            }
            out << "],\"property_coverage_delta\":" << vector.property_progress.property_coverage_delta
                << "},"
                << "\"protocol_semantic\":{"
                << "\"session_phase\":" << quote_json(vector.protocol_semantic.session_phase) << ","
                << "\"request_class\":" << quote_json(vector.protocol_semantic.request_class) << ","
                << "\"response_class\":" << quote_json(vector.protocol_semantic.response_class) << ","
                << "\"close_or_reset_seen\":" << (vector.protocol_semantic.close_or_reset_seen ? "true" : "false") << ","
                << "\"parser_state_id\":" << vector.protocol_semantic.parser_state_id
                << "},"
                << "\"mutation_hint\":{"
                << "\"recommended_gap_delta_ms\":" << vector.mutation_hint.recommended_gap_delta_ms << ","
                << "\"candidate_next_event_classes\":" << string_array_json(vector.mutation_hint.candidate_next_event_classes) << ","
                << "\"retry_hint\":" << (vector.mutation_hint.retry_hint ? "true" : "false") << ","
                << "\"keepalive_hint\":" << (vector.mutation_hint.keepalive_hint ? "true" : "false") << ","
                << "\"silence_hint\":" << (vector.mutation_hint.silence_hint ? "true" : "false")
                << "},"
                << "\"explainability\":{"
                << "\"dominant_property_id\":" << quote_json(vector.explainability.dominant_property_id) << ","
                << "\"decisive_transition_id\":" << vector.explainability.decisive_transition_id << ","
                << "\"critical_deadline_source\":" << quote_json(vector.explainability.critical_deadline_source) << ","
                << "\"shortest_witness_summary\":" << quote_json(vector.explainability.shortest_witness_summary)
                << "}"
                << "}";
            return out.str();
        }

        FeedbackVector filtered_feedback_vector(FeedbackChannelMask mask, FeedbackVector vector) {
            if ((mask & feedback_channel_mask(FeedbackChannel::Frontier)) == 0) {
                vector.frontier = FrontierFeedback{};
            }
            if ((mask & feedback_channel_mask(FeedbackChannel::Zone)) == 0) {
                vector.zone = ZoneFeedback{};
            }
            if ((mask & feedback_channel_mask(FeedbackChannel::Obligation)) == 0) {
                vector.obligation = ObligationFeedback{};
            }
            if ((mask & feedback_channel_mask(FeedbackChannel::PropertyProgress)) == 0) {
                vector.property_progress = PropertyProgressFeedback{};
            }
            if ((mask & feedback_channel_mask(FeedbackChannel::ProtocolSemantic)) == 0) {
                vector.protocol_semantic = ProtocolSemanticFeedback{};
            }
            if ((mask & feedback_channel_mask(FeedbackChannel::MutationHint)) == 0) {
                vector.mutation_hint = MutationHintFeedback{};
            }
            if ((mask & feedback_channel_mask(FeedbackChannel::Explainability)) == 0) {
                vector.explainability = ExplainabilityFeedback{};
            }
            return vector;
        }

        TimedTraceEvent make_timed_trace_event(const RawTimedEvent& raw_event, std::uint64_t event_index) {
            TimedTraceEvent event;
            event.event_index = event_index;
            event.timestamp_ms = raw_event.time.second;
            event.raw = raw_event;
            populate_trace_semantics_from_raw(event);
            event.close_or_reset_seen = derive_close_or_reset(event);
            return event;
        }

        std::string timed_trace_event_json_impl(const TimedTraceEvent& event) {
            std::ostringstream out;
            out << "{"
                << "\"event_index\":" << event.event_index << ","
                << "\"timestamp_ms\":" << event.timestamp_ms << ","
                << "\"t_send_ms\":" << number_or_null_json(event.t_send_ms) << ","
                << "\"t_first_response_ms\":" << number_or_null_json(event.t_first_response_ms) << ","
                << "\"t_done_ms\":" << number_or_null_json(event.t_done_ms) << ","
                << "\"gap_prev_ms\":" << number_or_null_json(event.gap_prev_ms) << ","
                << "\"direction\":" << quote_json(event.direction) << ","
                << "\"session_phase\":" << quote_json(event.session_phase) << ","
                << "\"request_class\":" << quote_json(event.request_class) << ","
                << "\"response_class\":" << quote_json(event.response_class) << ","
                << "\"close_or_reset_seen\":" << (event.close_or_reset_seen ? "true" : "false") << ","
                << "\"parser_state_id\":" << event.parser_state_id << ","
                << "\"candidate_next_event_classes\":" << string_array_json(event.candidate_next_event_classes) << ","
                << "\"raw\":{"
                << "\"time_lower\":" << event.raw.time.first << ","
                << "\"time_upper\":" << event.raw.time.second << ","
                << "\"propositions\":" << quote_json(event.raw.propositions) << ","
                << "\"source\":" << quote_json(event.raw.source) << ","
                << "\"line\":" << event.raw.line
                << "}"
                << "}";
            return out.str();
        }

    } // namespace

    FeedbackChannelMask all_feedback_channels() {
        return feedback_channel_mask(FeedbackChannel::Frontier) |
               feedback_channel_mask(FeedbackChannel::Zone) |
               feedback_channel_mask(FeedbackChannel::Obligation) |
               feedback_channel_mask(FeedbackChannel::PropertyProgress) |
               feedback_channel_mask(FeedbackChannel::ProtocolSemantic) |
               feedback_channel_mask(FeedbackChannel::MutationHint) |
               feedback_channel_mask(FeedbackChannel::Explainability);
    }

    std::string feedback_channel_name(FeedbackChannel channel) {
        switch (channel) {
            case FeedbackChannel::Frontier: return "frontier";
            case FeedbackChannel::Zone: return "zone";
            case FeedbackChannel::Obligation: return "obligation";
            case FeedbackChannel::PropertyProgress: return "progress";
            case FeedbackChannel::ProtocolSemantic: return "protocol";
            case FeedbackChannel::MutationHint: return "hint";
            case FeedbackChannel::Explainability: return "explain";
        }
        return "unknown";
    }

    std::string boundary_class_name(BoundaryClass boundary_class) {
        switch (boundary_class) {
            case BoundaryClass::Unknown: return "unknown";
            case BoundaryClass::SafeInterior: return "safe-interior";
            case BoundaryClass::NearDeadline: return "near-deadline";
            case BoundaryClass::CrossedDeadline: return "crossed-deadline";
            case BoundaryClass::AmbiguityBand: return "ambiguity-band";
        }
        return "unknown";
    }

    std::string monitor_answer_name(monitaal::monitor_answer_e answer) {
        std::ostringstream out;
        out << answer;
        return out.str();
    }

    std::string monitor_backend_name(MonitorBackend backend) {
        switch (backend) {
            case MonitorBackend::ConcreteProjected:
                return "concrete";
            case MonitorBackend::NativeBdd:
                return "bdd";
        }
        return "unknown";
    }

    MonitorBackend parse_monitor_backend(const std::string& name) {
        const auto lowered = to_lower_copy(trim(name));
        if (lowered == "concrete" || lowered == "projected" || lowered == "projected-concrete") {
            return MonitorBackend::ConcreteProjected;
        }
        if (lowered == "bdd" || lowered == "native-bdd" || lowered == "native_bdd") {
            return MonitorBackend::NativeBdd;
        }
        throw std::runtime_error("unknown monitor backend: " + name);
    }

    FeedbackChannelMask parse_feedback_channels_csv(const std::string& csv) {
        FeedbackChannelMask mask = 0;
        bool explicit_zero_mask = false;
        for (const auto& token : split_csv(csv)) {
            const auto lowered = to_lower_copy(token);
            if (lowered == "none" || lowered == "verdict" || lowered == "verdict-only") {
                if (mask != 0) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                explicit_zero_mask = true;
            } else if (lowered == "frontier") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::Frontier);
            } else if (lowered == "zone") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::Zone);
            } else if (lowered == "obligation") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::Obligation);
            } else if (lowered == "progress" || lowered == "property-progress") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::PropertyProgress);
            } else if (lowered == "protocol" || lowered == "protocol-semantic") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::ProtocolSemantic);
            } else if (lowered == "hint" || lowered == "mutation-hint") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::MutationHint);
            } else if (lowered == "explain" || lowered == "explainability") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= feedback_channel_mask(FeedbackChannel::Explainability);
            } else if (lowered == "all") {
                if (explicit_zero_mask) {
                    throw std::runtime_error("feedback channel 'none' / 'verdict-only' may not be combined with other channels");
                }
                mask |= all_feedback_channels();
            } else {
                throw std::runtime_error("unknown feedback channel: " + token);
            }
        }
        if (explicit_zero_mask) {
            return kVerdictOnlyChannelMaskSentinel;
        }
        return mask == 0 ? all_feedback_channels() : mask;
    }

    bool is_satisfiable(const monitaal::TA& automaton, SatisfiabilitySemantics semantics) {
        const auto initial_state = monitaal::symbolic_state_t(
                automaton.initial_location(),
                automaton.number_of_clocks());

        if (semantics == SatisfiabilitySemantics::Finite) {
            return initial_state.is_included_in(
                    monitaal::Fixpoint<monitaal::symbolic_state_t>::reach(
                            monitaal::Fixpoint<monitaal::symbolic_state_t>::accept_states(automaton),
                            automaton));
        }

        return initial_state.is_included_in(
                monitaal::Fixpoint<monitaal::symbolic_state_t>::buchi_accept_fixpoint(automaton));
    }

    bool is_satisfiable(const monitaal::TAwithBDDEdges& automaton, SatisfiabilitySemantics semantics) {
        const auto initial_state = monitaal::symbolic_state_t(
                automaton.initial_location(),
                automaton.number_of_clocks());

        if (semantics == SatisfiabilitySemantics::Finite) {
            return initial_state.is_included_in(
                    BddFixpoint<monitaal::symbolic_state_t>::reach(
                            BddFixpoint<monitaal::symbolic_state_t>::accept_states(automaton),
                            automaton));
        }

        return initial_state.is_included_in(
                BddFixpoint<monitaal::symbolic_state_t>::buchi_accept_fixpoint(automaton));
    }

    PositiveMonitorAutomaton compile_positive_monitor_automaton_from_formula(const std::string& formula,
                                                                             const CompileOptions& options) {
        ScopedCoutRedirect redirect(options.verbose);

        bdd_init(1000, 100);
        try {
            monitaal::TA positive = compile_one_formula(formula, options);
            std::vector<std::string> alphabet = monitor_alphabet;

            clear_bdd_build_state();
            bdd_done();
            monitor_concrete_labels = false;
            return PositiveMonitorAutomaton{positive, alphabet};
        } catch (...) {
            clear_bdd_build_state();
            bdd_done();
            monitor_concrete_labels = false;
            throw;
        }
    }

    PositiveBddMonitorAutomaton compile_positive_bdd_monitor_automaton_from_formula(const std::string& formula,
                                                                                     const CompileOptions& options) {
        const auto positive = compile_positive_monitor_automaton_from_formula(formula, options);
        const auto propositions = extract_proposition_indices(formula);
        return PositiveBddMonitorAutomaton{
                lift_concrete_monitor_automaton_to_bdd(positive.automaton, positive.alphabet, propositions),
                positive.alphabet,
                propositions};
    }

    MonitorAutomata compile_monitor_automata_from_formula(const std::string& formula,
                                                          const CompileOptions& options) {
        PositiveMonitorAutomaton positive = compile_positive_monitor_automaton_from_formula(formula, options);

        ScopedCoutRedirect redirect(options.verbose);

        bdd_init(1000, 100);
        try {
            monitaal::TA negative = compile_one_formula("!(" + formula + ")", options);

            if (positive.alphabet != monitor_alphabet) {
                throw std::runtime_error("positive and negative automata use different alphabets");
            }

            clear_bdd_build_state();
            bdd_done();
            monitor_concrete_labels = false;
            return MonitorAutomata{positive.automaton, negative, positive.alphabet};
        } catch (...) {
            clear_bdd_build_state();
            bdd_done();
            monitor_concrete_labels = false;
            throw;
        }
    }

    BddMonitorAutomata compile_bdd_monitor_automata_from_formula(const std::string& formula,
                                                                 const CompileOptions& options) {
        shutdown_bdd_runtime_manager_if_needed();
        auto concrete_automata = compile_monitor_automata_from_formula(formula, options);
        const auto propositions = extract_proposition_indices(formula);
        const auto alphabet = concrete_automata.alphabet;

        return BddMonitorAutomata{
                lift_concrete_monitor_automaton_to_bdd(concrete_automata.positive, alphabet, propositions),
                lift_concrete_monitor_automaton_to_bdd(concrete_automata.negative, alphabet, propositions),
                alphabet,
                propositions};
    }

    MonitorAutomata compile_monitor_automata_from_file(const std::string& path,
                                                       const CompileOptions& options) {
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("could not open formula file: " + path);
        }

        std::stringstream buffer;
        buffer << input.rdbuf();
        return compile_monitor_automata_from_formula(buffer.str(), options);
    }

    BddMonitorAutomata compile_bdd_monitor_automata_from_file(const std::string& path,
                                                              const CompileOptions& options) {
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("could not open formula file: " + path);
        }

        std::stringstream buffer;
        buffer << input.rdbuf();
        return compile_bdd_monitor_automata_from_formula(buffer.str(), options);
    }

    PropertyBundle compile_property_bundle_from_formula(const std::string& formula,
                                                        const CompileOptions& options) {
        auto automata = compile_monitor_automata_from_formula(formula, options);
        auto positive_locations = build_location_metadata_map(automata.positive);
        auto negative_locations = build_location_metadata_map(automata.negative);
        return PropertyBundle{
                std::move(automata),
                std::move(positive_locations),
                std::move(negative_locations)};
    }

    BddPropertyBundle compile_bdd_property_bundle_from_formula(const std::string& formula,
                                                               const CompileOptions& options) {
        auto automata = compile_bdd_monitor_automata_from_formula(formula, options);
        auto positive_locations = build_location_metadata_map(automata.positive);
        auto negative_locations = build_location_metadata_map(automata.negative);
        return BddPropertyBundle{
                std::move(automata),
                std::move(positive_locations),
                std::move(negative_locations)};
    }

    PropertyBundle compile_property_bundle_from_file(const std::string& path,
                                                     const CompileOptions& options) {
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("could not open formula file: " + path);
        }

        std::stringstream buffer;
        buffer << input.rdbuf();
        return compile_property_bundle_from_formula(buffer.str(), options);
    }

    BddPropertyBundle compile_bdd_property_bundle_from_file(const std::string& path,
                                                            const CompileOptions& options) {
        std::ifstream input(path);
        if (!input) {
            throw std::runtime_error("could not open formula file: " + path);
        }

        std::stringstream buffer;
        buffer << input.rdbuf();
        return compile_bdd_property_bundle_from_formula(buffer.str(), options);
    }

    StdinEventSource::StdinEventSource(std::istream& input, std::ostream* prompt)
            : _input(input), _prompt(prompt) {}

    std::optional<RawTimedEvent> StdinEventSource::next() {
        std::string line;
        while (true) {
            if (_prompt) {
                *_prompt << "Next event: ";
                _prompt->flush();
            }
            if (!std::getline(_input, line)) {
                return std::nullopt;
            }
            ++_line;
            const std::string stripped = trim(line);
            if (stripped.empty()) {
                continue;
            }
            if (stripped == "q") {
                return std::nullopt;
            }
            return parse_raw_event_line(line, "stdin", _line);
        }
    }

    FileEventSource::FileEventSource(std::istream& input, std::string source_name)
            : _input(input), _source_name(std::move(source_name)) {}

    std::optional<RawTimedEvent> FileEventSource::next() {
        std::string line;
        while (std::getline(_input, line)) {
            ++_line;
            if (trim(line).empty()) {
                continue;
            }
            return parse_raw_event_line(line, _source_name, _line);
        }

        return std::nullopt;
    }

    EventCodec::EventCodec(std::vector<std::string> alphabet, bool ignore_unknown_propositions)
            : _alphabet(std::move(alphabet)),
              _ignore_unknown_propositions(ignore_unknown_propositions) {
        for (size_t i = 0; i < _alphabet.size(); ++i) {
            _index_by_name.insert({_alphabet[i], i});
        }
    }

    const std::vector<std::string>& EventCodec::alphabet() const {
        return _alphabet;
    }

    std::string EventCodec::encode_proposition_set(const std::string& propositions) const {
        const std::string text = trim(propositions);
        std::string label(_alphabet.size(), '0');

        if (text == "-") {
            return label.empty() ? "-" : label;
        }

        std::set<std::string> seen;
        size_t begin = 0;
        while (begin <= text.size()) {
            size_t end = text.find(',', begin);
            if (end == std::string::npos) {
                end = text.size();
            }

            const std::string name = trim(text.substr(begin, end - begin));
            if (name.empty()) {
                throw std::runtime_error("empty proposition name in event");
            }
            if (name == "-") {
                throw std::runtime_error("'-' must be used alone for the empty proposition set");
            }

            const auto found = _index_by_name.find(name);
            if (found == _index_by_name.end()) {
                if (_ignore_unknown_propositions) {
                    if (end == text.size()) {
                        break;
                    }
                    begin = end + 1;
                    continue;
                }
                throw std::runtime_error("unknown proposition in event: " + name);
            }
            if (seen.insert(name).second) {
                label[found->second] = '1';
            }

            if (end == text.size()) {
                break;
            }
            begin = end + 1;
        }

        return label.empty() ? "-" : label;
    }

    monitaal::interval_input EventCodec::to_timed_input(const RawTimedEvent& event) const {
        try {
            return monitaal::interval_input(event.time, encode_proposition_set(event.propositions));
        } catch (const std::exception& e) {
            throw std::runtime_error(event.source + ":" + std::to_string(event.line) + ": " + e.what());
        }
    }

    monitaal::concrete_input EventCodec::to_concrete_input(const RawTimedEvent& event) const {
        if (event.time.first != event.time.second) {
            throw std::runtime_error(event.source + ":" + std::to_string(event.line) +
                                     ": concrete monitoring requires point timestamps");
        }
        try {
            return monitaal::concrete_input(static_cast<monitaal::concrete_time_t>(event.time.second),
                                            encode_proposition_set(event.propositions));
        } catch (const std::exception& e) {
            throw std::runtime_error(event.source + ":" + std::to_string(event.line) + ": " + e.what());
        }
    }

    MultiFeedbackChannelBus::MultiFeedbackChannelBus(FeedbackSettings settings) : _settings(std::move(settings)) {
        if (_settings.enabled_channels == 0) {
            _settings.enabled_channels = all_feedback_channels();
        }
    }

    const FeedbackSettings& MultiFeedbackChannelBus::settings() const {
        return _settings;
    }

    bool MultiFeedbackChannelBus::enabled(FeedbackChannel channel) const {
        if (_settings.enabled_channels == kVerdictOnlyChannelMaskSentinel) {
            return false;
        }
        return (_settings.enabled_channels & feedback_channel_mask(channel)) != 0;
    }

    FeedbackChannelMask MultiFeedbackChannelBus::enabled_mask() const {
        if (_settings.enabled_channels == kVerdictOnlyChannelMaskSentinel) {
            return 0;
        }
        return _settings.enabled_channels;
    }

    FeedbackFrame MultiFeedbackChannelBus::filter(FeedbackFrame frame) const {
        frame.channel_mask = enabled_mask();
        frame.feedback = filtered_feedback_vector(enabled_mask(), std::move(frame.feedback));
        return frame;
    }

    MonitorSession::~MonitorSession() = default;

    MonitorSession::MonitorSession(PropertyBundle bundle,
                                   FeedbackSettings settings,
                                   MonitorBackend backend)
            : _bundle(std::move(bundle)),
              _codec(_bundle->automata.alphabet, settings.ignore_unknown_propositions),
              _settings(std::move(settings)),
              _bus(_settings),
              _backend(backend) {
        _settings = _bus.settings();
        _interval_monitor.emplace(_bundle->automata.positive, _bundle->automata.negative);
        _concrete_slack_active = _settings.enable_concrete_slack;
        if (_concrete_slack_active) {
            _concrete_monitor.emplace(_bundle->automata.positive, _bundle->automata.negative);
        }
    }

    MonitorSession::MonitorSession(BddPropertyBundle bundle, FeedbackSettings settings)
            : _bdd_bundle(std::move(bundle)),
              _codec(_bdd_bundle->automata.alphabet, settings.ignore_unknown_propositions),
              _settings(std::move(settings)),
              _bus(_settings),
              _backend(MonitorBackend::NativeBdd) {
        _settings = _bus.settings();
        _bdd_codec = std::make_unique<BddEventCodec>(_bdd_bundle->automata.alphabet,
                                                     _bdd_bundle->automata.propositions,
                                                     _settings.ignore_unknown_propositions);
        _bdd_interval_monitor =
                std::make_unique<BddMonitor<monitaal::symbolic_state_t>>(
                        _bdd_bundle->automata.positive,
                        _bdd_bundle->automata.negative);
        _concrete_slack_active = false;
    }

    MonitorSession MonitorSession::from_formula(const std::string& formula,
                                                const CompileOptions& compile_options,
                                                const FeedbackSettings& feedback_settings,
                                                MonitorBackend backend) {
        if (backend == MonitorBackend::NativeBdd) {
            return MonitorSession(compile_bdd_property_bundle_from_formula(formula, compile_options), feedback_settings);
        }
        return MonitorSession(compile_property_bundle_from_formula(formula, compile_options),
                              feedback_settings,
                              backend);
    }

    MonitorSession MonitorSession::from_file(const std::string& path,
                                             const CompileOptions& compile_options,
                                             const FeedbackSettings& feedback_settings,
                                             MonitorBackend backend) {
        if (backend == MonitorBackend::NativeBdd) {
            return MonitorSession(compile_bdd_property_bundle_from_file(path, compile_options), feedback_settings);
        }
        return MonitorSession(compile_property_bundle_from_file(path, compile_options),
                              feedback_settings,
                              backend);
    }

    const PropertyBundle& MonitorSession::bundle() const {
        if (!_bundle.has_value()) {
            throw std::runtime_error("Concrete property bundle is only available for the projected backend");
        }
        return *_bundle;
    }

    const BddPropertyBundle& MonitorSession::bdd_bundle() const {
        if (!_bdd_bundle.has_value()) {
            throw std::runtime_error("BDD property bundle is only available for the Native-BDD backend");
        }
        return *_bdd_bundle;
    }

    const EventCodec& MonitorSession::codec() const {
        return _codec;
    }

    const FeedbackSettings& MonitorSession::settings() const {
        return _settings;
    }

    MonitorBackend MonitorSession::backend() const {
        return _backend;
    }

    monitaal::monitor_answer_e MonitorSession::verdict() const {
        return _last_verdict;
    }

    bool MonitorSession::concrete_slack_active() const {
        return _concrete_slack_active && _concrete_monitor.has_value();
    }

    std::size_t MonitorSession::positive_active_state_count() const {
        if (_backend == MonitorBackend::NativeBdd) {
            return _bdd_interval_monitor->positive_state_estimate().size();
        }
        return _interval_monitor->positive_state_estimate().size();
    }

    std::size_t MonitorSession::negative_active_state_count() const {
        if (_backend == MonitorBackend::NativeBdd) {
            return _bdd_interval_monitor->negative_state_estimate().size();
        }
        return _interval_monitor->negative_state_estimate().size();
    }

    std::size_t MonitorSession::total_active_state_count() const {
        return positive_active_state_count() + negative_active_state_count();
    }

    void MonitorSession::ensure_anchor() {
        if (_anchored) {
            return;
        }
        const RawTimedEvent anchor_event{{0, 0}, "-", "internal", 0};
        if (_backend == MonitorBackend::NativeBdd) {
            _last_verdict = _bdd_interval_monitor->input(_bdd_codec->to_timed_input(anchor_event));
            _anchored = true;
            return;
        }
        _interval_monitor->input(_codec.to_timed_input(anchor_event));
        if (_concrete_monitor.has_value()) {
            _concrete_monitor->input(_codec.to_concrete_input(anchor_event));
        }
        _last_verdict = _interval_monitor->status();
        _anchored = true;
    }

    FeedbackFrame MonitorSession::step(const RawTimedEvent& event) {
        TimedTraceEvent trace_event = make_timed_trace_event(event, _next_event_index);
        return step(trace_event);
    }

    FeedbackFrame MonitorSession::step(const TimedTraceEvent& original_event) {
        ensure_anchor();
        const auto previous_verdict = _last_verdict;

        TimedTraceEvent event = original_event;
        if (event.raw.source.empty()) {
            event.raw.source = "runtime";
        }
        event.event_index = _next_event_index;
        if (event.timestamp_ms == 0 && event.raw.time.second != 0) {
            event.timestamp_ms = event.raw.time.second;
        }
        populate_trace_semantics_from_raw(event);
        if ((event.session_phase.empty() || event.session_phase == "unknown") &&
            event.gap_prev_ms.has_value() &&
            event.gap_prev_ms.value() >
                static_cast<std::int64_t>(_settings.near_deadline_threshold_ms)) {
            event.session_phase = "idle";
        }
        if (event.session_phase.empty()) {
            event.session_phase = "unknown";
        }
        if (event.request_class.empty()) {
            event.request_class = "unknown";
        }
        if (event.response_class.empty()) {
            event.response_class = "unknown";
        }
        event.close_or_reset_seen = derive_close_or_reset(event);

        if (_backend == MonitorBackend::NativeBdd) {
            const auto input = _bdd_codec->to_timed_input(event.raw);
            _last_verdict = _bdd_interval_monitor->input(input);

            FeedbackFrame frame;
            frame.run_id = _settings.run_id;
            frame.event_index = _next_event_index;
            frame.property_set_id = _settings.property_set_id;
            frame.verdict = _last_verdict;
            frame.timestamp_ms = event.timestamp_ms;
            frame.channel_mask = _bus.enabled_mask();
            ++_next_event_index;
            return frame;
        }

        const auto input = _codec.to_timed_input(event.raw);
        _last_verdict = _interval_monitor->input(input);

        if (_concrete_monitor.has_value() && event.raw.time.first == event.raw.time.second) {
            try {
                _concrete_monitor->input(_codec.to_concrete_input(event.raw));
            } catch (...) {
                _concrete_monitor.reset();
                _concrete_slack_active = false;
            }
        } else if (_concrete_monitor.has_value()) {
            _concrete_monitor.reset();
            _concrete_slack_active = false;
        }

        const auto positive_symbolic = _interval_monitor->positive_state_estimate();
        const auto negative_symbolic = _interval_monitor->negative_state_estimate();

        FrontierFeedback frontier_feedback;
        frontier_feedback.frontier_size_pos = positive_symbolic.size();
        frontier_feedback.frontier_size_neg = negative_symbolic.size();
        frontier_feedback.pos_frontier_hash = frontier_signature_hash(positive_symbolic);
        frontier_feedback.neg_frontier_hash = frontier_signature_hash(negative_symbolic);
        std::uint64_t combined_frontier_signature = kFNVOffset;
        hash_combine_u64(combined_frontier_signature, frontier_feedback.pos_frontier_hash);
        hash_combine_u64(combined_frontier_signature, frontier_feedback.neg_frontier_hash);
        frontier_feedback.frontier_novelty = _frontier_visit_counts.emplace(combined_frontier_signature, 1).second;
        if (!frontier_feedback.frontier_novelty) {
            ++_frontier_visit_counts[combined_frontier_signature];
        }
        _last_frontier_signature = combined_frontier_signature;

        SlackSummary slack_summary;
        std::vector<monitaal::concrete_state_t> positive_concrete;
        std::vector<monitaal::concrete_state_t> negative_concrete;
        bool concrete_zone_available = false;
        if (_concrete_monitor.has_value()) {
            positive_concrete = _concrete_monitor->positive_state_estimate();
            negative_concrete = _concrete_monitor->negative_state_estimate();
            accumulate_state_slack(positive_concrete, _bundle->automata.positive,
                                   _settings.near_deadline_threshold_ms, slack_summary);
            accumulate_state_slack(negative_concrete, _bundle->automata.negative,
                                   _settings.near_deadline_threshold_ms, slack_summary);
            slack_summary.exact = true;
            concrete_zone_available = true;
        }

        ZoneFeedback zone_feedback;
        zone_feedback.zone_hash = timed_zone_hash(positive_symbolic, negative_symbolic,
                                                  positive_concrete, negative_concrete,
                                                  slack_summary, concrete_zone_available);
        _last_zone_hash = zone_feedback.zone_hash;
        zone_feedback.min_slack_ms = slack_summary.min_slack_ms;
        zone_feedback.slack_exact = slack_summary.exact;
        zone_feedback.violated_guard_count = slack_summary.violated_count;
        zone_feedback.near_deadline_count = slack_summary.near_deadline_count;
        zone_feedback.boundary_class = classify_boundary(slack_summary,
                                                         frontier_feedback.frontier_size_pos,
                                                         frontier_feedback.frontier_size_neg,
                                                         _settings.near_deadline_threshold_ms);

        std::uint64_t obligation_phase_mask = 0;
        std::uint32_t active_obligation_count = 0;
        for (const auto& state : positive_symbolic) {
            if (const auto found = _bundle->positive_locations.find(state.location()); found != _bundle->positive_locations.end()) {
                obligation_phase_mask |= found->second.obligation_phase_mask;
                if (found->second.obligation_phase_mask != 0) {
                    ++active_obligation_count;
                }
            }
        }
        for (const auto& state : negative_symbolic) {
            if (const auto found = _bundle->negative_locations.find(state.location()); found != _bundle->negative_locations.end()) {
                obligation_phase_mask |= found->second.obligation_phase_mask;
                if (found->second.obligation_phase_mask != 0) {
                    ++active_obligation_count;
                }
            }
        }

        ObligationFeedback obligation_feedback;
        obligation_feedback.active_obligation_count = active_obligation_count;
        obligation_feedback.obligation_phase_mask = obligation_phase_mask;
        if (active_obligation_count > _last_active_obligation_count) {
            obligation_feedback.opened_now = active_obligation_count - _last_active_obligation_count;
        } else if (active_obligation_count < _last_active_obligation_count) {
            obligation_feedback.satisfied_now = _last_active_obligation_count - active_obligation_count;
        }
        if (previous_verdict == monitaal::INCONCLUSIVE && _last_verdict == monitaal::NEGATIVE) {
            obligation_feedback.expired_now = std::max<std::uint32_t>(obligation_feedback.expired_now, 1);
        }
        _last_active_obligation_count = active_obligation_count;
        _last_obligation_phase_mask = obligation_phase_mask;

        PropertyProgressFeedback progress_feedback;
        const int current_progress_bin = progress_bin_for(_last_verdict, zone_feedback.boundary_class);
        progress_feedback.property_progress_vector.push_back(current_progress_bin);
        const std::uint64_t progress_bit = 1ULL << static_cast<std::uint64_t>(current_progress_bin);
        if ((_seen_progress_bins & progress_bit) == 0) {
            progress_feedback.newly_reached_progress_bins.push_back(current_progress_bin);
            progress_feedback.property_coverage_delta = 1;
            _seen_progress_bins |= progress_bit;
        }
        _last_progress_vector = progress_feedback.property_progress_vector;

        ProtocolSemanticFeedback protocol_feedback;
        protocol_feedback.session_phase = event.session_phase;
        protocol_feedback.request_class = event.request_class;
        protocol_feedback.response_class = event.response_class;
        protocol_feedback.close_or_reset_seen = event.close_or_reset_seen;
        protocol_feedback.parser_state_id = event.parser_state_id;

        MutationHintFeedback mutation_feedback;
        if (zone_feedback.min_slack_ms > 1) {
            mutation_feedback.recommended_gap_delta_ms = std::max<std::int64_t>(1, zone_feedback.min_slack_ms / 2);
        } else if (zone_feedback.boundary_class == BoundaryClass::CrossedDeadline) {
            mutation_feedback.recommended_gap_delta_ms = -1;
        }
        mutation_feedback.candidate_next_event_classes = derive_candidate_classes(event);
        mutation_feedback.retry_hint = (_last_verdict == monitaal::NEGATIVE) ||
                                       (zone_feedback.boundary_class == BoundaryClass::NearDeadline) ||
                                       (zone_feedback.boundary_class == BoundaryClass::AmbiguityBand);
        mutation_feedback.keepalive_hint = derive_keepalive_hint(
                event, protocol_feedback, zone_feedback);
        mutation_feedback.silence_hint = zone_feedback.boundary_class == BoundaryClass::AmbiguityBand;

        ExplainabilityFeedback explainability_feedback;
        explainability_feedback.dominant_property_id = _settings.property_set_id;
        explainability_feedback.critical_deadline_source = slack_summary.critical_source;
        explainability_feedback.shortest_witness_summary =
                "verdict=" + monitor_answer_name(_last_verdict) +
                ", boundary=" + boundary_class_name(zone_feedback.boundary_class) +
                ", frontier=(" + std::to_string(frontier_feedback.frontier_size_pos) + "," +
                std::to_string(frontier_feedback.frontier_size_neg) + ")";

        FeedbackFrame frame;
        frame.run_id = _settings.run_id;
        frame.event_index = _next_event_index;
        frame.property_set_id = _settings.property_set_id;
        frame.verdict = _last_verdict;
        frame.timestamp_ms = event.timestamp_ms;
        frame.feedback.frontier = frontier_feedback;
        frame.feedback.zone = zone_feedback;
        frame.feedback.obligation = obligation_feedback;
        frame.feedback.property_progress = progress_feedback;
        frame.feedback.protocol_semantic = protocol_feedback;
        frame.feedback.mutation_hint = mutation_feedback;
        frame.feedback.explainability = explainability_feedback;
        frame.semantic_state_id = semantic_state_hash(frontier_feedback, zone_feedback,
                                                      obligation_feedback, protocol_feedback);
        explainability_feedback.decisive_transition_id = frame.semantic_state_id ^ stable_hash(_settings.run_id) ^
                                                         static_cast<std::uint64_t>(frame.event_index);
        frame.feedback.explainability = explainability_feedback;
        frame = _bus.filter(std::move(frame));

        ++_next_event_index;
        return frame;
    }

    std::string MonitorSession::timed_trace_event_json(const TimedTraceEvent& event) const {
        return timed_trace_event_json_impl(event);
    }

    std::string MonitorSession::feedback_frame_json(const FeedbackFrame& frame) const {
        std::ostringstream out;
        out << "{"
            << "\"run_id\":" << quote_json(frame.run_id) << ","
            << "\"event_index\":" << frame.event_index << ","
            << "\"property_set_id\":" << quote_json(frame.property_set_id) << ","
            << "\"verdict\":" << quote_json(monitor_answer_name(frame.verdict)) << ","
            << "\"semantic_state_id\":" << frame.semantic_state_id << ","
            << "\"channel_mask\":" << frame.channel_mask << ","
            << "\"timestamp_ms\":" << frame.timestamp_ms << ","
            << "\"feedback\":" << feedback_vector_json(frame.feedback)
            << "}";
        return out.str();
    }

    FeedbackJsonlLogger::FeedbackJsonlLogger(std::ostream& output) : _output(output) {}

    void FeedbackJsonlLogger::write_event_feedback(const MonitorSession& session,
                                                   const TimedTraceEvent& event,
                                                   const FeedbackFrame& frame) {
        const auto& settings = session.settings();
        TimedTraceEvent logged_event = event;
        if (is_unknown_class(logged_event.request_class)) {
            logged_event.request_class = frame.feedback.protocol_semantic.request_class;
        }
        if (is_unknown_class(logged_event.response_class)) {
            logged_event.response_class = frame.feedback.protocol_semantic.response_class;
        }
        if (logged_event.session_phase.empty() || logged_event.session_phase == "unknown") {
            logged_event.session_phase = frame.feedback.protocol_semantic.session_phase;
        }
        if (logged_event.parser_state_id == 0) {
            logged_event.parser_state_id = frame.feedback.protocol_semantic.parser_state_id;
        }
        if (logged_event.candidate_next_event_classes.empty()) {
            logged_event.candidate_next_event_classes = frame.feedback.mutation_hint.candidate_next_event_classes;
        }
        if (!logged_event.close_or_reset_seen) {
            logged_event.close_or_reset_seen = frame.feedback.protocol_semantic.close_or_reset_seen;
        }

        const double elapsed_sec = static_cast<double>(logged_event.timestamp_ms) / 1000.0;
        const std::string case_id = settings.run_id + "-e" + std::to_string(frame.event_index);
        const bool slack_available = frame.feedback.zone.slack_exact ||
                                     frame.feedback.zone.min_slack_ms >= 0 ||
                                     frame.feedback.zone.violated_guard_count > 0 ||
                                     frame.feedback.zone.near_deadline_count > 0;
        const std::string slack_json = slack_available
                                       ? std::to_string(frame.feedback.zone.min_slack_ms)
                                       : "null";
        const std::size_t frontier_width =
                frame.feedback.frontier.frontier_size_pos + frame.feedback.frontier.frontier_size_neg;

        _output << "{"
                << "\"schema_version\":\"rvem.raw.v1\","
                << "\"event_type\":\"property_eval\","
                << "\"campaign\":" << quote_json(settings.campaign) << ","
                << "\"subject\":" << quote_json(settings.subject) << ","
                << "\"fuzzer\":" << quote_json(settings.fuzzer_name) << ","
                << "\"variant\":" << quote_json(settings.mode) << ","
                << "\"mode\":" << quote_json(settings.mode) << ","
                << "\"run_id\":" << quote_json(settings.run_id) << ","
                << "\"elapsed_sec\":" << elapsed_sec << ","
                << "\"timestamp\":" << quote_json(std::to_string(logged_event.timestamp_ms)) << ","
                << "\"case_id\":" << quote_json(case_id) << ","
                << "\"property_id\":" << quote_json(frame.property_set_id) << ","
                << "\"verdict\":" << quote_json(monitor_answer_name(frame.verdict)) << ","
                << "\"slack_ms\":" << slack_json << ","
                << "\"deadline_ms\":null,"
                << "\"timed_trace_event\":" << session.timed_trace_event_json(logged_event) << ","
                << "\"feedback_frame\":" << session.feedback_frame_json(frame)
                << "}\n";

        _output << "{"
                << "\"schema_version\":\"rvem.raw.v1\","
                << "\"event_type\":\"semantic_state\","
                << "\"campaign\":" << quote_json(settings.campaign) << ","
                << "\"subject\":" << quote_json(settings.subject) << ","
                << "\"fuzzer\":" << quote_json(settings.fuzzer_name) << ","
                << "\"variant\":" << quote_json(settings.mode) << ","
                << "\"mode\":" << quote_json(settings.mode) << ","
                << "\"run_id\":" << quote_json(settings.run_id) << ","
                << "\"elapsed_sec\":" << elapsed_sec << ","
                << "\"state_id\":" << quote_json(std::to_string(frame.semantic_state_id)) << ","
                << "\"region\":" << quote_json(frame.feedback.protocol_semantic.session_phase) << ","
                << "\"monitor_state_count\":" << frontier_width << ","
                << "\"frontier_width\":" << frontier_width << ","
                << "\"verdict\":" << quote_json(monitor_answer_name(frame.verdict)) << ","
                << "\"timed_trace_event\":" << session.timed_trace_event_json(logged_event) << ","
                << "\"feedback_frame\":" << session.feedback_frame_json(frame)
                << "}\n";

        if (frame.verdict == monitaal::NEGATIVE || frame.verdict == monitaal::POSITIVE) {
            const double gap_sec = logged_event.gap_prev_ms.has_value()
                                   ? static_cast<double>(*logged_event.gap_prev_ms) / 1000.0
                                   : 0.0;
            _output << "{"
                    << "\"schema_version\":\"rvem.raw.v1\","
                    << "\"event_type\":\"case_result\","
                    << "\"campaign\":" << quote_json(settings.campaign) << ","
                    << "\"subject\":" << quote_json(settings.subject) << ","
                    << "\"fuzzer\":" << quote_json(settings.fuzzer_name) << ","
                    << "\"variant\":" << quote_json(settings.mode) << ","
                    << "\"mode\":" << quote_json(settings.mode) << ","
                    << "\"run_id\":" << quote_json(settings.run_id) << ","
                    << "\"elapsed_sec\":" << elapsed_sec << ","
                    << "\"case_id\":" << quote_json(case_id) << ","
                    << "\"start_sec\":" << std::max(0.0, elapsed_sec - gap_sec) << ","
                    << "\"end_sec\":" << elapsed_sec << ","
                    << "\"outcome\":" << quote_json(frame.verdict == monitaal::NEGATIVE ? "violation" : "ok") << ","
                    << "\"property_id\":" << quote_json(frame.property_set_id) << ","
                    << "\"slack_ms\":" << slack_json << ","
                    << "\"timed_trace_event\":" << session.timed_trace_event_json(logged_event) << ","
                    << "\"feedback_frame\":" << session.feedback_frame_json(frame)
                    << "}\n";
        }
    }

    void FeedbackJsonlLogger::write_run_outcome(const MonitorSession& session,
                                                std::uint64_t events_seen,
                                                std::uint64_t last_timestamp_ms,
                                                monitaal::monitor_answer_e final_verdict) {
        const auto& settings = session.settings();
        const double elapsed_sec = static_cast<double>(last_timestamp_ms) / 1000.0;
        _output << "{"
                << "\"schema_version\":\"rvem.raw.v1\","
                << "\"event_type\":\"ablation_result\","
                << "\"campaign\":" << quote_json(settings.campaign) << ","
                << "\"subject\":" << quote_json(settings.subject) << ","
                << "\"fuzzer\":" << quote_json(settings.fuzzer_name) << ","
                << "\"variant\":" << quote_json(settings.mode) << ","
                << "\"mode\":" << quote_json(settings.mode) << ","
                << "\"run_id\":" << quote_json(settings.run_id) << ","
                << "\"elapsed_sec\":" << elapsed_sec << ","
                << "\"ablation\":" << quote_json(settings.mode) << ","
                << "\"execs_total\":" << events_seen << ","
                << "\"cases_total\":" << events_seen << ","
                << "\"bugs_total\":0,"
                << "\"violations_total\":" << (final_verdict == monitaal::NEGATIVE ? 1 : 0) << ","
                << "\"yield_total\":" << (final_verdict == monitaal::NEGATIVE ? 1 : 0) << ","
                << "\"property_id\":" << quote_json(settings.property_set_id) << ","
                << "\"final_verdict\":" << quote_json(monitor_answer_name(final_verdict)) << ","
                << "\"concrete_slack_active\":" << (session.concrete_slack_active() ? "true" : "false") << ","
                << "\"events_seen\":" << events_seen
                << "}\n";
    }

} // namespace mightypplcpp
