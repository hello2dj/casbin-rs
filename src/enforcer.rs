use std::path::{Path, PathBuf};

use eval::{to_value, Expr};

use crate::effect::{DefaultEffector, Effect, Effector};
use crate::error::Error;
use crate::model::Model;
use crate::model::{get_function_map, FunctionMap};
use crate::persist::Adapter;
use crate::rbac::{DefaultRoleManager, RoleManager};

#[derive(Debug)]
pub struct DefaultEnforcer();

impl DefaultEnforcer {
    pub fn new<A: Adapter>(
        model: Model,
        policy: A,
    ) -> Result<Enforcer<A, DefaultRoleManager, DefaultEffector>, Error> {
        Enforcer::new(model, policy, DefaultRoleManager::new(10), DefaultEffector::new())
    }
}

/// Enforcer is the main interface for authorization enforcement and policy management.
#[derive(Debug)]
pub struct Enforcer<A: Adapter, RM: RoleManager, E: Effector> {
    model: Model,
    function_map: FunctionMap,
    adapter: A,
    role_manager: RM,
    effector: E,
    auto_build_role_links: bool,
}

impl<A: Adapter, RM: RoleManager, E: Effector> Enforcer<A, RM, E> {
    /// Create an instance of an Enforcer from a `model` and `policy`.
    pub fn new(
        model: Model,
        policy: A,
        role_manager: RM,
        effector: E,
    ) -> Result<Enforcer<A, RM, E>, Error> {
        let mut enforcer = Enforcer {
            model,
            function_map: get_function_map(),
            adapter: policy,
            role_manager,
            effector,
            auto_build_role_links: true,
        };

        enforcer.load_policy()?;

        Ok(enforcer)
    }

    /// Rebuild the role inheritance relations.
    fn build_role_links(&mut self) -> Result<(), Error> {
        self.role_manager.clear()?;
        self.model.build_role_links(&mut self.role_manager)?;
        Ok(())
    }

    /// Reload the policy from source.
    fn load_policy(&mut self) -> Result<(), Error> {
        self.model.clear_policy();
        self.adapter.load_policy(&mut self.model)?;

        if self.auto_build_role_links {
            self.build_role_links()?;
        }

        Ok(())
    }

    /// Decide whether `subject` can access `object` with the operation `action`.

    // TODO: enforce does not handle matcherResults.
    pub fn enforce(&self, subject: &str, object: &str, action: &str) -> Result<bool, Error> {
        let mut policy_effects: Vec<Effect> = vec![];

        let expr_string = &self.model.data.get("m").unwrap().get("m").unwrap().value;
        let expr = Expr::new(expr_string.clone());

        for policy in &self.model.data["p"]["p"].policy {
            let expr = Expr::new(expr_string.clone())
                .value("r_sub", subject)
                .value("r_obj", object)
                .value("r_act", action)
                .value("p_sub", &policy[0])
                .value("p_obj", &policy[1])
                .value("p_act", &policy[2]);

            let result = expr.exec().map_err(|e| Error::Eval(e))?;
            
            if (result == to_value(false)) {
                policy_effects.push(Effect::Indeterminate);
                continue;
            }

            // TODO(sduquette): Assuming that the effect of rules is Allow for now.
            policy_effects.push(Effect::Allow);
        }

        let effect_expr = &self.model.data.get("e").unwrap().get("e").unwrap().value;
        self.effector.merge_effects(effect_expr, policy_effects, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::persist::file_adapter::FileAdapter;

    #[test]
    fn test_match_in_memory() {
        let mut model = Model::new();

        assert_eq!(model.add_def("r", "r", "sub, obj, act").unwrap(), true);
	    assert_eq!(model.add_def("p", "p", "sub, obj, act").unwrap(), true);
	    assert_eq!(model.add_def("e", "e", "some(where (p.eft == allow))").unwrap(), true);
	    assert_eq!(model.add_def("m", "m", "(r.sub == p.sub) && (r.obj == p.obj) && (r.act == p.act)").unwrap(), true);

        let adapter = FileAdapter::new("examples/basic_policy.csv", false);
        let enforcer =
            DefaultEnforcer::new(model, adapter).expect("failed to create instance of Enforcer");
        
        assert_eq!(enforcer.enforce("alice", "data1", "read").unwrap(), true);
        assert_eq!(enforcer.enforce("alice", "data2", "read").unwrap(), false);
        assert_eq!(enforcer.enforce("bob", "data2", "write").unwrap(), true);
        assert_eq!(enforcer.enforce("bob", "data2", "read").unwrap(), false);
    }
}
