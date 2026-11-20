// Module template for the differential probe. The build step copies this directory,
// rewrites the replace target to the locked source tree, and adds the tree's own require
// block so pinned dependency versions apply unchanged.
module billow.local/mihomo-probe

go 1.26

require github.com/metacubex/mihomo v0.0.0

// The tree's config package uses temporaryUpdateGeneral through linkname; the probe program
// blank-imports hub so that, like the released binary, the function exists at link time.

replace github.com/metacubex/mihomo => ./mihomo
