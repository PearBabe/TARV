#include "BddRuntimeMonitor.h"
#include "MightyPPLMonitor.h"

#include <cctype>
#include <set>

namespace mightypplcpp {

    namespace {

        std::string trim_bdd_event_text(const std::string& input) {
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

    } // namespace

    namespace detail {

        bool bdd_label_matches_valuation(const bdd& label, const std::map<int, bool>& valuation) {
            if (label == bddtrue) {
                return true;
            }
            if (label == bddfalse) {
                return false;
            }

            const int variable = bdd_var(label);
            const auto found = valuation.find(variable);
            const bool value = found != valuation.end() ? found->second : false;
            return bdd_label_matches_valuation(value ? bdd_high(label) : bdd_low(label), valuation);
        }

    } // namespace detail

    BddEventCodec::BddEventCodec(std::vector<std::string> alphabet, bool ignore_unknown_propositions)
            : _alphabet(std::move(alphabet)),
              _ignore_unknown_propositions(ignore_unknown_propositions) {
        for (size_t i = 0; i < _alphabet.size(); ++i) {
            _bdd_var_by_name.insert({_alphabet[i], static_cast<int>(i + 1)});
        }
    }

    BddEventCodec::BddEventCodec(std::vector<std::string> alphabet,
                                 std::map<std::string, int> proposition_indices,
                                 bool ignore_unknown_propositions)
            : _alphabet(std::move(alphabet)),
              _ignore_unknown_propositions(ignore_unknown_propositions) {
        for (const auto& name : _alphabet) {
            const auto found = proposition_indices.find(name);
            if (found == proposition_indices.end()) {
                throw std::runtime_error("missing proposition index for BDD event codec symbol: " + name);
            }
            _bdd_var_by_name.insert({name, found->second});
        }
    }

    const std::vector<std::string>& BddEventCodec::alphabet() const {
        return _alphabet;
    }

    std::map<int, bool> BddEventCodec::encode_proposition_set(const std::string& propositions) const {
        const std::string text = trim_bdd_event_text(propositions);
        std::map<int, bool> valuation;

        std::set<std::string> present;
        if (text != "-") {
            size_t begin = 0;
            while (begin <= text.size()) {
                size_t end = text.find(',', begin);
                if (end == std::string::npos) {
                    end = text.size();
                }

                const std::string name = trim_bdd_event_text(text.substr(begin, end - begin));
                if (name.empty()) {
                    throw std::runtime_error("empty proposition name in event");
                }
                if (name == "-") {
                    throw std::runtime_error("'-' must be used alone for the empty proposition set");
                }

                const auto found = _bdd_var_by_name.find(name);
                if (found == _bdd_var_by_name.end()) {
                    if (!_ignore_unknown_propositions) {
                        throw std::runtime_error("unknown proposition in event: " + name);
                    }
                } else {
                    present.insert(name);
                }

                if (end == text.size()) {
                    break;
                }
                begin = end + 1;
            }
        }

        for (const auto& [name, var] : _bdd_var_by_name) {
            valuation.insert({var, present.count(name) != 0});
        }

        return valuation;
    }

    BddTimedInput BddEventCodec::to_timed_input(const RawTimedEvent& event) const {
        try {
            return BddTimedInput{event.time, encode_proposition_set(event.propositions)};
        } catch (const std::exception& e) {
            throw std::runtime_error(event.source + ":" + std::to_string(event.line) + ": " + e.what());
        }
    }

    template class BddSingleMonitor<monitaal::symbolic_state_t>;
    template class BddSingleMonitor<monitaal::concrete_state_t>;
    template class BddMonitor<monitaal::symbolic_state_t>;
    template class BddMonitor<monitaal::concrete_state_t>;

} // namespace mightypplcpp
