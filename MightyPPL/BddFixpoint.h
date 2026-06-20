#pragma once

#include "TAwithBDDEdges.h"
#include "state.h"

#include "bdd.h"

#include <vector>

namespace mightypplcpp {

    template<class state_t>
    class BddFixpoint {
    public:
        static monitaal::symbolic_state_map_t<state_t>
        reach(const monitaal::symbolic_state_map_t<state_t>& states,
              const monitaal::TAwithBDDEdges& automaton);

        static monitaal::symbolic_state_map_t<state_t>
        accept_states(const monitaal::TAwithBDDEdges& automaton);

        static monitaal::symbolic_state_map_t<state_t>
        buchi_accept_fixpoint(const monitaal::TAwithBDDEdges& automaton);

    private:
        static bool bdd_label_is_satisfiable(const monitaal::bdd_label_t& label);
    };

    template<class state_t>
    bool BddFixpoint<state_t>::bdd_label_is_satisfiable(const monitaal::bdd_label_t& label) {
        return !(label == bddfalse);
    }

    template<class state_t>
    monitaal::symbolic_state_map_t<state_t>
    BddFixpoint<state_t>::reach(const monitaal::symbolic_state_map_t<state_t>& states,
                                const monitaal::TAwithBDDEdges& automaton) {
        monitaal::symbolic_state_map_t<state_t> waiting;
        monitaal::symbolic_state_map_t<state_t> passed;

        // Keep MoniTAal's backward DBM semantics, but traverse native BDD edges
        // directly. Non-false BDD labels are existentially satisfiable letters.
        for (const auto& [_, s] : states) {
            for (const auto& edge : automaton.bdd_edges_to(s.location())) {
                if (!bdd_label_is_satisfiable(edge.bdd_label())) {
                    continue;
                }

                auto state = s;
                state.do_transition_backward(edge);
                state.restrict(automaton.locations().at(edge.from()).invariant());
                waiting.insert(state);
            }
        }

        while (!waiting.is_empty()) {
            state_t state = waiting.begin()->second;
            waiting.remove(state.location());

            if (passed.has_state(state.location()) &&
                state.is_included_in(passed.at(state.location()))) {
                continue;
            }

            passed.insert(state);

            for (const auto& edge : automaton.bdd_edges_to(state.location())) {
                if (!bdd_label_is_satisfiable(edge.bdd_label())) {
                    continue;
                }

                auto predecessor = state;
                predecessor.do_transition_backward(edge);
                predecessor.restrict(automaton.locations().at(edge.from()).invariant());
                waiting.insert(predecessor);
            }
        }

        return passed;
    }

    template<class state_t>
    monitaal::symbolic_state_map_t<state_t>
    BddFixpoint<state_t>::accept_states(const monitaal::TAwithBDDEdges& automaton) {
        monitaal::symbolic_state_map_t<state_t> states;

        for (const auto& [_, location] : automaton.locations()) {
            if (location.is_accept()) {
                states.insert(state_t::unconstrained(location.id(), automaton.number_of_clocks()));
            }
        }

        return states;
    }

    template<class state_t>
    monitaal::symbolic_state_map_t<state_t>
    BddFixpoint<state_t>::buchi_accept_fixpoint(const monitaal::TAwithBDDEdges& automaton) {
        auto reach_a = reach(accept_states(automaton), automaton);

        std::vector<monitaal::location_id_t> erase_list;
        for (const auto& [location_id, _] : reach_a) {
            if (!automaton.locations().at(location_id).is_accept()) {
                erase_list.push_back(location_id);
            }
        }

        for (const auto& location_id : erase_list) {
            reach_a.remove(location_id);
        }
        erase_list.clear();

        auto reach_b = reach(reach_a, automaton);

        while (!reach_a.equals(reach_b)) {
            reach_a = reach_b;

            for (const auto& [location_id, _] : reach_b) {
                if (!automaton.locations().at(location_id).is_accept()) {
                    erase_list.push_back(location_id);
                }
            }

            for (const auto& location_id : erase_list) {
                reach_b.remove(location_id);
            }
            erase_list.clear();

            reach_b = reach(reach_b, automaton);
        }

        return reach_a;
    }

} // namespace mightypplcpp
