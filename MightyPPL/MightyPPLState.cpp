#include "MightyPPL.h"

namespace mightypplcpp {

    const char* spec_file = nullptr;
    const char* out_file = nullptr;
    std::optional<bool> out_format = std::nullopt;    // true: tck, false: xml
    bool out_flatten = true;
    bool comp_flatten = false;
    bool out_fin = false;
    bool debug = false;
    bool back = true;
    bool monitor_concrete_labels = false;
    std::vector<std::string> monitor_alphabet;

    monitaal::TAwithBDDEdges varphi = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
    monitaal::TAwithBDDEdges div = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);
    std::vector<monitaal::TAwithBDDEdges> temporal_components;
    monitaal::TAwithBDDEdges model = monitaal::TAwithBDDEdges("dummy", {}, {}, {}, 0);

} // namespace mightypplcpp
