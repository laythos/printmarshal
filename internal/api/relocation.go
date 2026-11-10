package api

import (
	"errors"
	"net/http"

	"printmarshal/internal/model"
	"printmarshal/internal/store"
)

// resolveDeviceAddress settles a device's pending address (recorded when its
// identifiers answered from another address): "confirm" moves the record
// there, "dismiss" drops it. Either way the decision is audited.
func (s *Server) resolveDeviceAddress(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Action != "confirm" && body.Action != "dismiss" {
		writeErr(w, http.StatusBadRequest, `action must be "confirm" or "dismiss"`)
		return
	}
	id := r.PathValue("id")
	before, err := s.Store.GetDevice(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	var d *model.Device
	if body.Action == "confirm" {
		d, err = s.Store.ConfirmRelocation(r.Context(), id)
	} else {
		d, err = s.Store.DismissRelocation(r.Context(), id)
	}
	if errors.Is(err, store.ErrNoPendingRelocation) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.audit(r.Context(), r, "device.address."+body.Action, id,
		map[string]any{"address": before.Address, "pendingAddress": before.PendingAddress},
		map[string]any{"address": d.Address, "pendingAddress": d.PendingAddress}, "ok")
	s.publish(r, model.Event{Type: "device.updated", Data: d})
	writeJSON(w, http.StatusOK, d)
}
