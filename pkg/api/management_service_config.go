package api

import "github.com/bhangun/iket/pkg/config"

func cloneServices(in []config.Service) []config.Service {
	if len(in) == 0 {
		return nil
	}
	out := make([]config.Service, len(in))
	for i, svc := range in {
		out[i] = svc
		if len(svc.Routes) > 0 {
			out[i].Routes = make([]config.RouterConfig, len(svc.Routes))
			copy(out[i].Routes, svc.Routes)
		}
		if len(svc.Tags) > 0 {
			out[i].Tags = append([]string(nil), svc.Tags...)
		}
		if len(svc.Scopes) > 0 {
			out[i].Scopes = append([]string(nil), svc.Scopes...)
		}
	}
	return out
}
