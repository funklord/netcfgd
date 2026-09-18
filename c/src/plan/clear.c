/*
 * clear.c -- `on_unmanage = "clear"`, which is a state and not a transition.
 *
 * WHAT THE POLICY SAYS
 *   `managed = false` means netcfgd stops operating on a device and changes
 *   nothing, credentials included (0035). `on_unmanage = "clear"` says the
 *   desired state is that netcfgd owns *nothing* on it, so what it left behind
 *   comes off first (0037).
 *
 *   That is a state rather than a transition, which is why nothing here
 *   detects an edge: the teardown decides as if the device were not in the
 *   document, removes what is tagged as netcfgd's, and finds nothing to do on
 *   every plan after that. An empty plan is how an operator knows it is done.
 *
 * WHY THE DOCUMENT IS FILTERED RATHER THAN THE PASSES TAUGHT
 *   Four teardown passes already know how to remove what the document does not
 *   want. Filtering the document once beats teaching each of them about a
 *   policy none of them otherwise cares about -- and a pass added later would
 *   not know to ask, which is the failure this shape cannot have.
 *
 *   **Both lists, and the device list is the one that matters.** The Rust
 *   filtered only `interfaces`, which was complete while a link's existence was
 *   stated there; 0155 moved that onto the device, and `teardown_links` reads
 *   the device list accordingly -- so a clearing device stayed in the list,
 *   read as wanted, and was never deleted. `on_unmanage = "clear"` withdrew the
 *   addresses and routes and left the device standing, which is the one thing
 *   it exists to take away. project.md 10.16 is that defect; this port is
 *   written with it already closed.
 *
 * WHY THE FORWARD PASSES MUST NOT SEE THE FILTER
 *   Planning an address and removing it in the same plan is a loop, not a
 *   convergence. So `ncfg_builder_push` drops every action on an unmanaged
 *   device as it always has, and the exemption for a clearing one applies
 *   during teardown only -- which is the whole of what `tearing_down` is for.
 *
 * THE COPY IS SHALLOW, DELIBERATELY
 *   Two arrays are allocated and every string in them is still the document's.
 *   Nothing in a teardown writes through the document, the original outlives
 *   the plan, and a deep copy would be a second lifetime to get wrong for no
 *   answer that differs.
 */
#include "plan_internal.h"

#include <stdlib.h>

void ncfg_plan_clearing_collect(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->device_count; i++) {
		const ncfg_device_t *device = &builder->desired->devices[i];

		if (device->managed || device->on_unmanage != NCFG_ON_UNMANAGE_CLEAR) {
			continue;
		}
		ncfg_builder_note_string(builder, &builder->clearing, &builder->clearing_count,
		    device->name);
	}
}

int ncfg_plan_clearing(const ncfg_builder_t *builder, const char *name)
{
	return ncfg_plan_names(builder->clearing, builder->clearing_count, name);
}

void ncfg_plan_clearing_begin(ncfg_builder_t *builder)
{
	const ncfg_document_t *desired = builder->desired;
	ncfg_document_t       *copy;
	ncfg_interface_t      *interfaces = NULL;
	ncfg_device_t         *devices = NULL;
	size_t                 interface_count = 0;
	size_t                 device_count = 0;
	size_t                 i;

	builder->tearing_down = 1;
	if (builder->clearing_count == 0u) {
		return;
	}
	copy = malloc(sizeof(*copy));
	if (desired->interface_count != 0u) {
		interfaces = malloc(desired->interface_count * sizeof(*interfaces));
	}
	if (desired->device_count != 0u) {
		devices = malloc(desired->device_count * sizeof(*devices));
	}
	if (!copy || (desired->interface_count != 0u && !interfaces) ||
	    (desired->device_count != 0u && !devices)) {
		/*
		 * The plan is marked and the document is left alone, so the teardown
		 * runs against what the forward passes saw: nothing of the clearing
		 * device is removed, which is the safe direction for a build that is
		 * about to be discarded anyway.
		 */
		builder->plan->failed = 1;
		free(copy);
		free(interfaces);
		free(devices);
		return;
	}
	for (i = 0; i < desired->interface_count; i++) {
		if (ncfg_plan_clearing(builder, desired->interfaces[i].name)) {
			continue;
		}
		interfaces[interface_count++] = desired->interfaces[i];
	}
	for (i = 0; i < desired->device_count; i++) {
		if (ncfg_plan_clearing(builder, desired->devices[i].name)) {
			continue;
		}
		devices[device_count++] = desired->devices[i];
	}
	*copy = *desired;
	copy->interfaces = interfaces;
	copy->interface_count = interface_count;
	copy->devices = devices;
	copy->device_count = device_count;

	builder->unfiltered = desired;
	builder->filtered = copy;
	builder->desired = copy;
}

void ncfg_plan_clearing_end(ncfg_builder_t *builder)
{
	builder->tearing_down = 0;
	if (builder->filtered) {
		builder->desired = builder->unfiltered;
		free(builder->filtered->interfaces);
		free(builder->filtered->devices);
		free(builder->filtered);
		builder->filtered = NULL;
		builder->unfiltered = NULL;
	}
	free(builder->clearing);
	builder->clearing = NULL;
	builder->clearing_count = 0;
}
