package logic

import C "github.com/metacubex/mihomo/constant"

// Rules exposes the immutable parsed children for pure rule evaluation.
// Callers must not modify the returned slice or the rules it contains.
func (logic *Logic) Rules() []C.Rule { return logic.rules }

// SubRules exposes the immutable parsed subrule graph. Callers must not modify it.
func (logic *Logic) SubRules() map[string][]C.Rule { return logic.subRules }

// WithRules creates an independent evaluation view without copying sync.Once.
// The supplied children and subrules must already be immutable snapshots.
func (logic *Logic) WithRules(children []C.Rule, subRules map[string][]C.Rule) *Logic {
	return &Logic{Base: logic.Base, payload: logic.Payload(), adapter: logic.adapter,
		ruleType: logic.ruleType, rules: children, subRules: subRules}
}
