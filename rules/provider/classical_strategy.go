package provider

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"
)

type classicalStrategy struct {
	policyReady   bool
	policyInvalid bool
	rules         []C.Rule
	count         int
	parse         common.ParseRuleFunc
}

func (c *classicalStrategy) Behavior() P.RuleBehavior {
	return P.Classical
}

func (c *classicalStrategy) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	for _, rule := range c.rules {
		if m, _ := rule.Match(metadata, helper); m {
			return true
		}
	}

	return false
}

func (c *classicalStrategy) Count() int {
	return c.count
}

func (c *classicalStrategy) Reset() {
	c.policyReady, c.policyInvalid = false, false
	c.rules = nil
	c.count = 0
}

func (c *classicalStrategy) Insert(rule string) {
	r, err := c.payloadToRule(rule)
	if err != nil {
		c.policyInvalid = true
		log.Warnln("parse classical rule [%s] error: %s", rule, err.Error())
	} else {
		c.rules = append(c.rules, r)
		c.count++
	}
}

func (c *classicalStrategy) payloadToRule(rule string) (C.Rule, error) {
	tp, payload, target, params := common.ParseRulePayload(rule, false)
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return nil, fmt.Errorf("unsupported rule type on classical rule-set: %s", tp)
	}
	return c.parse(tp, payload, target, params, nil)
}

func (c *classicalStrategy) FinishInsert() { c.policyReady = true }

func (c *classicalStrategy) PolicyComplete() bool { return c.policyReady && !c.policyInvalid }
func (c *classicalStrategy) invalidatePolicy()    { c.policyInvalid = true }

func NewClassicalStrategy(parse common.ParseRuleFunc) *classicalStrategy {
	return &classicalStrategy{rules: []C.Rule{}, parse: parse}
}
