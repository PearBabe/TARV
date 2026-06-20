#include "BddFixpoint.h"

namespace mightypplcpp {

    template class BddFixpoint<monitaal::symbolic_state_t>;
    template class BddFixpoint<monitaal::delay_state_t>;
    template class BddFixpoint<monitaal::testing_state_t>;

} // namespace mightypplcpp
