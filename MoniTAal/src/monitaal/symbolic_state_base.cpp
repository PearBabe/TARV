/*
 * Copyright Thomas M. Grosen 
 * Created on 06/04/2024
 */

/*
 * This file is part of MoniTAal
 *
 * MoniTAal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MoniTAal is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with MoniTAal. If not, see <https://www.gnu.org/licenses/>.
 */

#include "symbolic_state_base.h"

#include <sstream>

namespace monitaal {

    symbolic_state_base::symbolic_state_base() : _location(0), _federation() {}

    symbolic_state_base::symbolic_state_base(location_id_t location, clock_index_t clocks) : 
            _location(location), _federation(clocks) {}

    void symbolic_state_base::down() {
        _federation.past();
    }

    void symbolic_state_base::restrict_to_zero(const clocks_t& clocks) {
        for (const auto& x : clocks) {
            _federation.restrict(x, 0, pardibaal::bound_t::non_strict(0));
        }
    }

    void symbolic_state_base::restrict(const constraints_t& constraints) {
        for (const auto& c : constraints)
            _federation.restrict(c);
    }

    void symbolic_state_base::free(const clocks_t& clocks) {
        for (const auto& x : clocks)
            _federation.free(x);
    }

    void symbolic_state_base::intersection(const symbolic_state_base& state) {
        if (state._location == _location)
            _federation.intersection(state._federation);
        else
            this->_federation.restrict(0,0, {-1, true});
    }

    void symbolic_state_base::add(const symbolic_state_base& state) {
        if (state.location() == _location)
            _federation.add(state._federation);
    }

    bool symbolic_state_base::do_transition(const edge_t& edge) {
        if (edge.from() != _location) return false;

        // If the transition is not possible, do nothing and return false
        if (not this->satisfies(edge.guard()))
            return false;

        if (!edge.guard().empty()) {
            for (auto& c : edge.guard())
                _federation.restrict(c);
        }

        for (const auto& r : edge.reset())
            _federation.assign(r, 0);

        _location = edge.to();
        return true;
    }

    void symbolic_state_base::do_transition_backward(const edge_t& edge) {

        if (edge.to() == _location) {
            _location = edge.from();

            this->down();
            this->restrict_to_zero(edge.reset());
            this->free(edge.reset());
            this->restrict(edge.guard());
            this->down();
        }
    }

    bool symbolic_state_base::is_empty() const {
        return _federation.is_empty();
    }

    relation_t symbolic_state_base::relation(const symbolic_state_base& state) const {
        if (state._location == _location) {
            return _federation.relation<false>(state._federation);
        }
        return relation_t::different();
    }

    bool symbolic_state_base::is_included_in(const symbolic_state_base &state) const {
        if (state._location == _location) {
            auto rel = _federation.relation<false>(state._federation);
            return rel.is_equal() || rel.is_subset();
        }
        return false;
    }

    bool symbolic_state_base::equals(const symbolic_state_base& state) const {
        return _federation.is_approx_equal(state._federation);
    }

    bool symbolic_state_base::satisfies(const constraint_t &constraint) const {
        return _federation.is_satisfying(constraint);
    }

    bool symbolic_state_base::satisfies(const constraints_t &constraints) const {
        return _federation.is_satisfying(constraints);
    }

    location_id_t symbolic_state_base::location() const {
        return _location;
    }

    Federation symbolic_state_base::federation() const { return _federation; }

    namespace {
        std::string bound_summary(const pardibaal::bound_t& bound) {
            if (bound.is_inf())
                return "inf";
            std::ostringstream out;
            out << (bound.is_strict() ? "<" : "<=") << bound.get_bound();
            return out.str();
        }
    }

    std::string symbolic_state_base::stable_summary() const {
        std::ostringstream out;
        out << "loc=" << _location << ";empty=" << is_empty() << ";fed=[";
        bool first_dbm = true;
        for (const auto& dbm : _federation) {
            if (first_dbm) first_dbm = false;
            else out << "|";
            out << "dim=" << dbm.dimension() << ":";
            bool first_bound = true;
            for (pardibaal::dim_t i = 0; i < dbm.dimension(); ++i) {
                for (pardibaal::dim_t j = 0; j < dbm.dimension(); ++j) {
                    if (first_bound) first_bound = false;
                    else out << ",";
                    out << i << "-" << j << bound_summary(dbm.at(i, j));
                }
            }
        }
        out << "]";
        return out.str();
    }

    void symbolic_state_base::print(std::ostream &out, const TA &T) const {
        out << T.locations().at(_location).name() << ' ' << _federation;
    }

}
