#pragma once

#include "Monitor.h"
#include "TA.h"
#include "TAwithBDDEdges.h"
#include "types.h"

#include <cstdint>
#include <istream>
#include <memory>
#include <map>
#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace mightypplcpp {

    class BddEventCodec;
    template<class state_t> class BddMonitor;

    struct CompileOptions {
        bool infinite = true;
        bool debug = false;
        bool simplify = true;
        bool verbose = false;
    };

    struct MonitorAutomata {
        monitaal::TA positive;
        monitaal::TA negative;
        std::vector<std::string> alphabet;
    };

    enum class SatisfiabilitySemantics {
        Infinite,
        Finite
    };

    enum class MonitorBackend {
        ConcreteProjected,
        NativeBdd
    };

    struct PositiveMonitorAutomaton {
        monitaal::TA automaton;
        std::vector<std::string> alphabet;
    };

    struct PositiveBddMonitorAutomaton {
        monitaal::TAwithBDDEdges automaton;
        std::vector<std::string> alphabet;
        std::map<std::string, int> propositions;
    };

    struct BddMonitorAutomata {
        monitaal::TAwithBDDEdges positive;
        monitaal::TAwithBDDEdges negative;
        std::vector<std::string> alphabet;
        std::map<std::string, int> propositions;
    };

    struct RawTimedEvent {
        monitaal::interval_t time;
        std::string propositions;
        std::string source;
        size_t line = 0;
    };

    enum class FeedbackChannel : std::uint32_t {
        Frontier = 1u << 0,
        Zone = 1u << 1,
        Obligation = 1u << 2,
        PropertyProgress = 1u << 3,
        ProtocolSemantic = 1u << 4,
        MutationHint = 1u << 5,
        Explainability = 1u << 6
    };

    using FeedbackChannelMask = std::uint32_t;

    enum class BoundaryClass : std::uint8_t {
        Unknown = 0,
        SafeInterior,
        NearDeadline,
        CrossedDeadline,
        AmbiguityBand
    };

    struct FeedbackSettings {
        std::string campaign = "standalone-monitor";
        std::string subject = "unknown-subject";
        std::string fuzzer_name = "bizonefuzz++";
        std::string mode = "full";
        std::string run_id = "run-0";
        std::string property_set_id = "property-set-0";
        FeedbackChannelMask enabled_channels = 0;
        std::uint32_t near_deadline_threshold_ms = 5;
        std::size_t exact_slack_frontier_limit = 16;
        bool enable_concrete_slack = true;
        bool log_internal_anchor = false;
        bool ignore_unknown_propositions = false;
    };

    struct FrontierFeedback {
        std::uint64_t pos_frontier_hash = 0;
        std::uint64_t neg_frontier_hash = 0;
        std::size_t frontier_size_pos = 0;
        std::size_t frontier_size_neg = 0;
        bool frontier_novelty = false;
    };

    struct ZoneFeedback {
        std::uint64_t zone_hash = 0;
        std::int64_t min_slack_ms = -1;
        bool slack_exact = false;
        BoundaryClass boundary_class = BoundaryClass::Unknown;
        std::uint32_t violated_guard_count = 0;
        std::uint32_t near_deadline_count = 0;
    };

    struct ObligationFeedback {
        std::uint32_t active_obligation_count = 0;
        std::uint32_t opened_now = 0;
        std::uint32_t satisfied_now = 0;
        std::uint32_t expired_now = 0;
        std::uint64_t obligation_phase_mask = 0;
    };

    struct PropertyProgressFeedback {
        std::vector<int> property_progress_vector;
        std::vector<int> newly_reached_progress_bins;
        std::uint32_t property_coverage_delta = 0;
    };

    struct ProtocolSemanticFeedback {
        std::string session_phase = "unknown";
        std::string request_class = "unknown";
        std::string response_class = "unknown";
        bool close_or_reset_seen = false;
        std::uint64_t parser_state_id = 0;
    };

    struct MutationHintFeedback {
        std::int64_t recommended_gap_delta_ms = 0;
        std::vector<std::string> candidate_next_event_classes;
        bool retry_hint = false;
        bool keepalive_hint = false;
        bool silence_hint = false;
    };

    struct ExplainabilityFeedback {
        std::string dominant_property_id;
        std::uint64_t decisive_transition_id = 0;
        std::string critical_deadline_source;
        std::string shortest_witness_summary;
    };

    struct FeedbackVector {
        FrontierFeedback frontier;
        ZoneFeedback zone;
        ObligationFeedback obligation;
        PropertyProgressFeedback property_progress;
        ProtocolSemanticFeedback protocol_semantic;
        MutationHintFeedback mutation_hint;
        ExplainabilityFeedback explainability;
    };

    struct FeedbackFrame {
        std::string run_id;
        std::uint64_t event_index = 0;
        std::string property_set_id;
        monitaal::monitor_answer_e verdict = monitaal::INCONCLUSIVE;
        std::uint64_t semantic_state_id = 0;
        FeedbackChannelMask channel_mask = 0;
        std::uint64_t timestamp_ms = 0;
        FeedbackVector feedback;
    };

    struct LocationMetadata {
        monitaal::location_id_t location_id = 0;
        std::string location_name;
        bool accepting = false;
        std::string invariant_text;
        std::string source_subformula;
        std::uint64_t obligation_phase_mask = 0;
        std::string timer_class = "generic";
        std::string protocol_semantic_anchor;
    };

    struct PropertyBundle {
        MonitorAutomata automata;
        std::unordered_map<monitaal::location_id_t, LocationMetadata> positive_locations;
        std::unordered_map<monitaal::location_id_t, LocationMetadata> negative_locations;
    };

    struct BddPropertyBundle {
        BddMonitorAutomata automata;
        std::unordered_map<monitaal::location_id_t, LocationMetadata> positive_locations;
        std::unordered_map<monitaal::location_id_t, LocationMetadata> negative_locations;
    };

    struct TimedTraceEvent {
        std::uint64_t event_index = 0;
        std::uint64_t timestamp_ms = 0;
        std::optional<std::uint64_t> t_send_ms;
        std::optional<std::uint64_t> t_first_response_ms;
        std::optional<std::uint64_t> t_done_ms;
        std::optional<std::int64_t> gap_prev_ms;
        std::string direction = "input";
        std::string session_phase = "unknown";
        std::string request_class = "unknown";
        std::string response_class = "unknown";
        bool close_or_reset_seen = false;
        std::uint64_t parser_state_id = 0;
        std::vector<std::string> candidate_next_event_classes;
        RawTimedEvent raw;
    };

    [[nodiscard]] constexpr FeedbackChannelMask feedback_channel_mask(FeedbackChannel channel) {
        return static_cast<FeedbackChannelMask>(channel);
    }

    [[nodiscard]] FeedbackChannelMask all_feedback_channels();
    [[nodiscard]] std::string feedback_channel_name(FeedbackChannel channel);
    [[nodiscard]] std::string boundary_class_name(BoundaryClass boundary_class);
    [[nodiscard]] std::string monitor_answer_name(monitaal::monitor_answer_e answer);
    [[nodiscard]] std::string monitor_backend_name(MonitorBackend backend);
    [[nodiscard]] MonitorBackend parse_monitor_backend(const std::string& name);
    [[nodiscard]] FeedbackChannelMask parse_feedback_channels_csv(const std::string& csv);

    [[nodiscard]] bool is_satisfiable(const monitaal::TA& automaton,
                                      SatisfiabilitySemantics semantics);
    [[nodiscard]] bool is_satisfiable(const monitaal::TAwithBDDEdges& automaton,
                                      SatisfiabilitySemantics semantics);

    PositiveMonitorAutomaton compile_positive_monitor_automaton_from_formula(const std::string& formula,
                                                                             const CompileOptions& options = {});
    PositiveBddMonitorAutomaton compile_positive_bdd_monitor_automaton_from_formula(const std::string& formula,
                                                                                     const CompileOptions& options = {});
    MonitorAutomata compile_monitor_automata_from_formula(const std::string& formula,
                                                          const CompileOptions& options = {});
    BddMonitorAutomata compile_bdd_monitor_automata_from_formula(const std::string& formula,
                                                                 const CompileOptions& options = {});
    MonitorAutomata compile_monitor_automata_from_file(const std::string& path,
                                                       const CompileOptions& options = {});
    BddMonitorAutomata compile_bdd_monitor_automata_from_file(const std::string& path,
                                                              const CompileOptions& options = {});
    PropertyBundle compile_property_bundle_from_formula(const std::string& formula,
                                                        const CompileOptions& options = {});
    BddPropertyBundle compile_bdd_property_bundle_from_formula(const std::string& formula,
                                                               const CompileOptions& options = {});
    PropertyBundle compile_property_bundle_from_file(const std::string& path,
                                                     const CompileOptions& options = {});
    BddPropertyBundle compile_bdd_property_bundle_from_file(const std::string& path,
                                                            const CompileOptions& options = {});

    class IEventSource {
    public:
        virtual ~IEventSource() = default;
        virtual std::optional<RawTimedEvent> next() = 0;
    };

    class StdinEventSource final : public IEventSource {
    public:
        explicit StdinEventSource(std::istream& input, std::ostream* prompt = nullptr);
        std::optional<RawTimedEvent> next() override;

    private:
        std::istream& _input;
        std::ostream* _prompt;
        size_t _line = 0;
    };

    class FileEventSource final : public IEventSource {
    public:
        FileEventSource(std::istream& input, std::string source_name);
        std::optional<RawTimedEvent> next() override;

    private:
        std::istream& _input;
        std::string _source_name;
        size_t _line = 0;
    };

    class RealtimeEventSource : public IEventSource {
    public:
        std::optional<RawTimedEvent> next() override = 0;
    };

    class EventCodec {
    public:
        EventCodec(std::vector<std::string> alphabet, bool ignore_unknown_propositions = false);

        [[nodiscard]] const std::vector<std::string>& alphabet() const;
        [[nodiscard]] std::string encode_proposition_set(const std::string& propositions) const;
        [[nodiscard]] monitaal::interval_input to_timed_input(const RawTimedEvent& event) const;
        [[nodiscard]] monitaal::concrete_input to_concrete_input(const RawTimedEvent& event) const;

    private:
        std::vector<std::string> _alphabet;
        std::map<std::string, size_t> _index_by_name;
        bool _ignore_unknown_propositions = false;
    };

    class MultiFeedbackChannelBus {
    public:
        explicit MultiFeedbackChannelBus(FeedbackSettings settings = {});

        [[nodiscard]] const FeedbackSettings& settings() const;
        [[nodiscard]] bool enabled(FeedbackChannel channel) const;
        [[nodiscard]] FeedbackChannelMask enabled_mask() const;
        [[nodiscard]] FeedbackFrame filter(FeedbackFrame frame) const;

    private:
        FeedbackSettings _settings;
    };

    class MonitorSession {
    public:
        ~MonitorSession();

        MonitorSession(PropertyBundle bundle,
                       FeedbackSettings settings = {},
                       MonitorBackend backend = MonitorBackend::ConcreteProjected);
        MonitorSession(BddPropertyBundle bundle, FeedbackSettings settings = {});

        static MonitorSession from_formula(const std::string& formula,
                                           const CompileOptions& compile_options = {},
                                           const FeedbackSettings& feedback_settings = {},
                                           MonitorBackend backend = MonitorBackend::ConcreteProjected);
        static MonitorSession from_file(const std::string& path,
                                        const CompileOptions& compile_options = {},
                                        const FeedbackSettings& feedback_settings = {},
                                        MonitorBackend backend = MonitorBackend::ConcreteProjected);

        [[nodiscard]] const PropertyBundle& bundle() const;
        [[nodiscard]] const BddPropertyBundle& bdd_bundle() const;
        [[nodiscard]] const EventCodec& codec() const;
        [[nodiscard]] const FeedbackSettings& settings() const;
        [[nodiscard]] MonitorBackend backend() const;
        [[nodiscard]] monitaal::monitor_answer_e verdict() const;
        [[nodiscard]] bool concrete_slack_active() const;
        [[nodiscard]] std::size_t positive_active_state_count() const;
        [[nodiscard]] std::size_t negative_active_state_count() const;
        [[nodiscard]] std::size_t total_active_state_count() const;

        FeedbackFrame step(const RawTimedEvent& event);
        FeedbackFrame step(const TimedTraceEvent& event);

        [[nodiscard]] std::string timed_trace_event_json(const TimedTraceEvent& event) const;
        [[nodiscard]] std::string feedback_frame_json(const FeedbackFrame& frame) const;

    private:
        std::optional<PropertyBundle> _bundle;
        std::optional<BddPropertyBundle> _bdd_bundle;
        EventCodec _codec;
        std::unique_ptr<BddEventCodec> _bdd_codec;
        FeedbackSettings _settings;
        MultiFeedbackChannelBus _bus;
        MonitorBackend _backend = MonitorBackend::ConcreteProjected;
        std::optional<monitaal::Interval_monitor> _interval_monitor;
        std::optional<monitaal::Concrete_monitor> _concrete_monitor;
        std::unique_ptr<BddMonitor<monitaal::symbolic_state_t>> _bdd_interval_monitor;
        bool _anchored = false;
        bool _concrete_slack_active = false;
        monitaal::monitor_answer_e _last_verdict = monitaal::INCONCLUSIVE;
        std::uint64_t _next_event_index = 0;
        std::uint64_t _last_frontier_signature = 0;
        std::uint64_t _last_zone_hash = 0;
        std::uint64_t _last_obligation_phase_mask = 0;
        std::uint32_t _last_active_obligation_count = 0;
        std::vector<int> _last_progress_vector;
        std::uint64_t _seen_progress_bins = 0;
        std::unordered_map<std::uint64_t, std::size_t> _frontier_visit_counts;

        void ensure_anchor();
    };

    class FeedbackJsonlLogger {
    public:
        explicit FeedbackJsonlLogger(std::ostream& output);

        void write_event_feedback(const MonitorSession& session,
                                  const TimedTraceEvent& event,
                                  const FeedbackFrame& frame);
        void write_run_outcome(const MonitorSession& session,
                               std::uint64_t events_seen,
                               std::uint64_t last_timestamp_ms,
                               monitaal::monitor_answer_e final_verdict);

    private:
        std::ostream& _output;
    };

} // namespace mightypplcpp
