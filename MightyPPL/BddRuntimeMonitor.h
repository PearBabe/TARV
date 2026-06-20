#pragma once

#include "BddFixpoint.h"
#include "TAwithBDDEdges.h"

#include "Monitor.h"
#include "state.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace mightypplcpp {

    struct RawTimedEvent;

    struct BddTimedInput {
        monitaal::interval_t time;
        std::map<int, bool> valuation;
    };

    class BddEventCodec {
    public:
        BddEventCodec(std::vector<std::string> alphabet, bool ignore_unknown_propositions = false);
        BddEventCodec(std::vector<std::string> alphabet,
                      std::map<std::string, int> proposition_indices,
                      bool ignore_unknown_propositions = false);

        [[nodiscard]] const std::vector<std::string>& alphabet() const;
        [[nodiscard]] std::map<int, bool> encode_proposition_set(const std::string& propositions) const;
        [[nodiscard]] BddTimedInput to_timed_input(const RawTimedEvent& event) const;

    private:
        std::vector<std::string> _alphabet;
        std::map<std::string, int> _bdd_var_by_name;
        bool _ignore_unknown_propositions = false;
    };

    namespace detail {

        template<class state_t>
        using accepting_state_t = typename std::conditional_t<
                std::is_base_of<monitaal::symbolic_state_base, state_t>::value,
                state_t,
                monitaal::symbolic_state_t>;

        [[nodiscard]] bool bdd_label_matches_valuation(const bdd& label,
                                                       const std::map<int, bool>& valuation);

        template<class state_t>
        void add_state_if_relevant(std::vector<state_t>& next_states,
                                   state_t state,
                                   const monitaal::symbolic_state_map_t<accepting_state_t<state_t>>& accepting_space,
                                   const monitaal::TAwithBDDEdges& automaton,
                                   bool inclusion,
                                   bool clock_abstraction) {
            state.intersection(accepting_space);
            if (state.is_empty()) {
                return;
            }

            bool add = true;
            bool replace = true;
            monitaal::relation_t relation = monitaal::relation_t::different();
            if (inclusion) {
                if (clock_abstraction) {
                    state.free(automaton.inactive_clocks().at(state.location()));
                }
                for (const auto& next_state : next_states) {
                    relation = state.relation(next_state);
                    if (relation.is_subset() || relation.is_equal()) {
                        add = false;
                    }
                    if (next_state.location() == state.location() &&
                        (relation.is_different() || relation.is_subset())) {
                        replace = false;
                    }
                }
            }

            if (add || replace) {
                if (replace) {
                    next_states.erase(std::remove_if(next_states.begin(), next_states.end(), [&state](const state_t& candidate) {
                        return state.location() == candidate.location();
                    }), next_states.end());
                }
                next_states.push_back(std::move(state));
            }
        }

    } // namespace detail

    template<class state_t>
    class BddSingleMonitor {
    public:
        explicit BddSingleMonitor(const monitaal::TAwithBDDEdges& automaton,
                                  const monitaal::settings_t& setting = monitaal::settings_t())
                : _automaton(automaton),
                  _accepting_space(BddFixpoint<detail::accepting_state_t<state_t>>::buchi_accept_fixpoint(automaton)),
                  _inclusion(setting.inclusion),
                  _clock_abstraction(setting.clock_abstraction) {
            state_t initial(_automaton.initial_location(), _automaton.number_of_clocks());
            initial.intersection(_accepting_space);
            if (initial.is_empty()) {
                _status = monitaal::OUT;
            } else {
                _status = monitaal::ACTIVE;
                _current_states = std::vector{initial};
            }
        }

        [[nodiscard]] monitaal::single_monitor_answer_e status() const {
            return _status;
        }

        monitaal::single_monitor_answer_e input(const BddTimedInput& input) {
            std::vector<state_t> next_states;
            bool input_matches_automaton = false;

            for (const auto& [location_id, _] : _automaton.locations()) {
                for (const auto& edge : _automaton.bdd_edges_from(location_id)) {
                    if (detail::bdd_label_matches_valuation(edge.bdd_label(), input.valuation)) {
                        input_matches_automaton = true;
                        break;
                    }
                }
                if (input_matches_automaton) {
                    break;
                }
            }

            if (!input_matches_automaton) {
                for (auto state : _current_states) {
                    state.delay(input.time);
                    if (state.satisfies(_automaton.locations().at(state.location()).invariant())) {
                        state.restrict(_automaton.locations().at(state.location()).invariant());
                        detail::add_state_if_relevant(next_states,
                                                      std::move(state),
                                                      _accepting_space,
                                                      _automaton,
                                                      _inclusion,
                                                      _clock_abstraction);
                    }
                }
            } else {
                for (auto state : _current_states) {
                    state.delay(input.time);
                    if (state.satisfies(_automaton.locations().at(state.location()).invariant())) {
                        state.restrict(_automaton.locations().at(state.location()).invariant());
                    } else {
                        continue;
                    }

                    for (const auto& edge : _automaton.bdd_edges_from(state.location())) {
                        if (!detail::bdd_label_matches_valuation(edge.bdd_label(), input.valuation)) {
                            continue;
                        }

                        auto next_state = state;
                        if (next_state.do_transition(edge) &&
                            next_state.satisfies(_automaton.locations().at(edge.to()).invariant())) {
                            next_state.restrict(_automaton.locations().at(edge.to()).invariant());
                            detail::add_state_if_relevant(next_states,
                                                          std::move(next_state),
                                                          _accepting_space,
                                                          _automaton,
                                                          _inclusion,
                                                          _clock_abstraction);
                        }
                    }
                }
            }

            _status = next_states.empty() ? monitaal::OUT : monitaal::ACTIVE;
            _current_states = std::move(next_states);
            return _status;
        }

        [[nodiscard]] std::vector<state_t> state_estimate() const {
            return _current_states;
        }

        [[nodiscard]] std::string feedback_summary() const {
            std::ostringstream out;
            out << "status=" << _status << ";states=[";
            bool first = true;
            for (const auto& state : _current_states) {
                if (first) {
                    first = false;
                } else {
                    out << "|";
                }
                out << state.stable_summary();
            }
            out << "]";
            return out.str();
        }

        void print_status(std::ostream& out) const {
            out << "Number of states: " << _current_states.size() << '\n';
        }

    private:
        monitaal::TAwithBDDEdges _automaton;
        monitaal::symbolic_state_map_t<detail::accepting_state_t<state_t>> _accepting_space;
        std::vector<state_t> _current_states;
        monitaal::single_monitor_answer_e _status = monitaal::OUT;
        bool _inclusion = false;
        bool _clock_abstraction = false;
    };

    template<class state_t>
    class BddMonitor {
    public:
        BddMonitor(const monitaal::TAwithBDDEdges& positive,
                   const monitaal::TAwithBDDEdges& negative,
                   const monitaal::settings_t& setting = monitaal::settings_t())
                : _monitor_pos(positive, setting),
                  _monitor_neg(negative, setting) {
            update_status_from_single_monitors();
        }

        monitaal::monitor_answer_e input(const std::vector<BddTimedInput>& input) {
            for (const auto& event : input) {
                _status = this->input(event);
                if (_status != monitaal::INCONCLUSIVE) {
                    break;
                }
            }
            return _status;
        }

        monitaal::monitor_answer_e input(const BddTimedInput& input) {
            const auto positive = _monitor_pos.input(input);
            const auto negative = _monitor_neg.input(input);

            assert((positive != monitaal::OUT || negative != monitaal::OUT) &&
                   "Error: Mismatch between positive and negative automata. Both are out\n");

            if (positive == monitaal::OUT) {
                _status = monitaal::NEGATIVE;
            } else if (negative == monitaal::OUT) {
                _status = monitaal::POSITIVE;
            }
            return _status;
        }

        [[nodiscard]] monitaal::monitor_answer_e status() const {
            return _status;
        }

        [[nodiscard]] std::vector<state_t> positive_state_estimate() const {
            return _monitor_pos.state_estimate();
        }

        [[nodiscard]] std::vector<state_t> negative_state_estimate() const {
            return _monitor_neg.state_estimate();
        }

        [[nodiscard]] monitaal::single_monitor_answer_e positive_monitor_status() const {
            return _monitor_pos.status();
        }

        [[nodiscard]] monitaal::single_monitor_answer_e negative_monitor_status() const {
            return _monitor_neg.status();
        }

        [[nodiscard]] std::string feedback_summary() const {
            std::ostringstream out;
            out << "verdict=" << _status
                << ";positive={" << _monitor_pos.feedback_summary()
                << "};negative={" << _monitor_neg.feedback_summary() << "}";
            return out.str();
        }

        void print_status(std::ostream& out) const {
            out << "Verdict: " << status() << '\n';
            out << "Positive:\n";
            _monitor_pos.print_status(out);
            out << "\nNegative:\n";
            _monitor_neg.print_status(out);
            out << '\n';
        }

    private:
        BddSingleMonitor<state_t> _monitor_pos;
        BddSingleMonitor<state_t> _monitor_neg;
        monitaal::monitor_answer_e _status = monitaal::INCONCLUSIVE;

        void update_status_from_single_monitors() {
            assert((_monitor_pos.status() != monitaal::OUT || _monitor_neg.status() != monitaal::OUT) &&
                   "Error: Mismatch between positive and negative automata. Both are out\n");
            if (_monitor_pos.status() == monitaal::OUT) {
                _status = monitaal::NEGATIVE;
            } else if (_monitor_neg.status() == monitaal::OUT) {
                _status = monitaal::POSITIVE;
            } else {
                _status = monitaal::INCONCLUSIVE;
            }
        }
    };

    using BddIntervalMonitor = BddMonitor<monitaal::symbolic_state_t>;
    using BddConcreteMonitor = BddMonitor<monitaal::concrete_state_t>;

} // namespace mightypplcpp
