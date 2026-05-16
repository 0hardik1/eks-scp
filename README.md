# eks-scp

Top 10 highest-impact AWS Organizations **Service Control Policies (SCPs)** for Amazon EKS, built on the seven new EKS-specific IAM condition keys that AWS released in [April 2026](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/).

For the in-depth explanation, risk analysis, working JSON, verification steps, and sources, see [`TOP_10_EKS_SCPS.md`](./TOP_10_EKS_SCPS.md). This README gives you enough context to understand the policies, deploy them safely, and reason about their limits.

## Layout

```
README.md            this file (overview, conventions, deployment guide)
TOP_10_EKS_SCPS.md   in-depth report: one section per SCP
scps/                deployable SCP JSON files, one per policy
```

## Background

### Why these SCPs exist

Before April 2026 the most security-sensitive EKS cluster settings (public API endpoint, envelope encryption key, deletion protection, control-plane scaling tier, Kubernetes version, zonal shift) were only governable *after the fact* by AWS Config rules, custom Lambdas, or post-creation alerting. By the time those fired, a misconfigured cluster was already running.

AWS's April 2026 release added EKS-specific IAM condition keys that are evaluated inside the request, at the time `eks:CreateCluster`, `eks:UpdateClusterConfig`, `eks:UpdateClusterVersion`, and `eks:AssociateEncryptionConfig` are called. That means SCPs can now **block misconfigured clusters from ever being created or weakened**, instead of detecting them after the damage is done.

### What an SCP is (and is not)

- An SCP is an AWS Organizations policy attached to an OU (or to the org root). It defines the **maximum** permissions that any principal in any account under that OU can ever have, regardless of identity-based or resource-based grants.
- SCPs **do not grant** permissions. A `Deny` statement in an SCP just caps what an otherwise-granted permission can do.
- SCPs **do not** apply to the management account, service-linked roles, or root credentials of member accounts. Plan your break-glass strategy accordingly.
- The policies in this repo are pure `Deny` policies that layer on top of your existing IAM grants. None of them broaden any access.

### The seven new condition keys

| Key | Type | Used in SCPs | Applies to |
|---|---|---|---|
| `eks:endpointPublicAccess` | Bool | 1, 2 | `CreateCluster`, `UpdateClusterConfig` |
| `eks:endpointPrivateAccess` | Bool | 3 | `CreateCluster`, `UpdateClusterConfig` |
| `eks:encryptionConfigProviderKeyArns` | ArrayOfString (KMS ARNs) | 4 | `CreateCluster`, `AssociateEncryptionConfig` |
| `eks:kubernetesVersion` | String (`MAJOR.MINOR`) | 5, 6 | `CreateCluster`, `UpdateClusterVersion` |
| `eks:deletionProtection` | Bool | 7, 8 | `CreateCluster`, `UpdateClusterConfig` |
| `eks:zonalShiftEnabled` | Bool | 9 | `CreateCluster`, `UpdateClusterConfig` |
| `eks:controlPlaneScalingTier` | String | 10 | `CreateCluster`, `UpdateClusterConfig` |

The authoritative table of condition keys, value types, and applicable actions is the [Service Authorization Reference for Amazon EKS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelastickubernetesservice.html). Open that page before deploying to confirm exact key spelling and any keys added since April 2026.

## Conventions used in every policy

These conventions are why the JSON in `scps/` looks the way it does. Understanding them is the difference between "this SCP works" and "this SCP silently allows the thing you thought it blocked."

- **`Effect: Deny`**. Every policy is a deny. SCPs cap permissions; they do not grant them.
- **`Resource: "*"`**. EKS condition keys are request-context keys, not resource keys. SCPs that gate API actions on request context use `Resource: "*"`.
- **Break-glass carve-out** (`ArnNotLike` against `aws:PrincipalArn`). Every policy exempts a placeholder break-glass role (`arn:aws:iam::*:role/BreakGlassEKSAdmin`) so a human operator can still recover from a self-inflicted lockout. Replace this with your real break-glass role ARN(s) before deploying.
- **AND semantics inside a `Condition` block**. Multiple top-level operator blocks inside one `Condition` are AND-ed together, so each policy reads as "deny when the misconfiguration check is true AND the caller is not the break-glass role." This is the documented IAM behaviour, see [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).
- **Null checks for "key omitted"**. Where a condition key could legitimately be left out of a request, an explicit `Null` operator is used so that the *absence* of the key is also denied, not just the wrong value (SCPs 4 and 7).
- **Narrow `Action` lists**. Each policy denies the minimum set of API actions needed for the guardrail, rather than blanket-denying `eks:*`.

## The 10 SCPs at a glance

| # | File | What it blocks | Why it matters |
|---|---|---|---|
| 1 | [`scps/01-deny-public-endpoint-at-create.json`](./scps/01-deny-public-endpoint-at-create.json) | Creating a cluster with a public API endpoint | The Kubernetes API server is the highest-value control plane in the account; putting it on the public Internet is the single most common cause of EKS data-exfiltration incidents |
| 2 | [`scps/02-deny-enabling-public-endpoint-on-update.json`](./scps/02-deny-enabling-public-endpoint-on-update.json) | Flipping an existing cluster's API endpoint to public | Closes the "create private, then quietly flip to public for debugging" posture-degradation pattern that SCP 1 alone cannot stop |
| 3 | [`scps/03-require-private-endpoint.json`](./scps/03-require-private-endpoint.json) | Creating or updating a cluster without the private endpoint enabled | Keeps in-VPC nodes, pods, and operators talking to the control plane over the AWS network instead of the public Internet |
| 4 | [`scps/04-require-approved-kms-cmk.json`](./scps/04-require-approved-kms-cmk.json) | Creating a cluster without envelope encryption using an approved customer-managed KMS CMK | Customer-managed KMS gives you separate key custody, CloudTrail decrypt logs, and the ability to revoke access to every secret in a cluster by disabling one key |
| 5 | [`scps/05-enforce-minimum-kubernetes-version-on-create.json`](./scps/05-enforce-minimum-kubernetes-version-on-create.json) | Creating a cluster pinned to a Kubernetes version below the organisational floor | Prevents "throwaway" clusters from being spun up on out-of-support versions where CVEs accumulate unpatched |
| 6 | [`scps/06-block-downgrade-or-deprecated-version-on-update.json`](./scps/06-block-downgrade-or-deprecated-version-on-update.json) | Updating an existing cluster to a Kubernetes version below the floor | Stops a compromised or careless principal from rolling a cluster back onto a deprecated version, side-stepping SCP 5 |
| 7 | [`scps/07-require-deletion-protection-on-create.json`](./scps/07-require-deletion-protection-on-create.json) | Creating a cluster without deletion protection | Deleted clusters are unrecoverable: every nodegroup, IAM-bound add-on, PVC reference, and the etcd encryption envelope go with them |
| 8 | [`scps/08-deny-disabling-deletion-protection.json`](./scps/08-deny-disabling-deletion-protection.json) | Disabling deletion protection on an existing cluster | Turns "disable protection then delete" into a two-principal action, since only the break-glass role can disable |
| 9 | [`scps/09-require-zonal-shift-enabled.json`](./scps/09-require-zonal-shift-enabled.json) | Creating or updating a cluster with zonal shift disabled | Cheapest material HA improvement: lets EKS automatically steer traffic away from an impaired Availability Zone |
| 10 | [`scps/10-restrict-control-plane-scaling-tier.json`](./scps/10-restrict-control-plane-scaling-tier.json) | Creating or updating a cluster with a non-approved control-plane scaling tier | Cost-and-compliance guardrail: forces tier changes through a documented change request rather than letting teams pick silently |

Each row links to the deployable JSON. The matching section in [`TOP_10_EKS_SCPS.md`](./TOP_10_EKS_SCPS.md) carries the full risk write-up, the condition-key and operator rationale, verification commands, and source citations.

## Before you deploy

Every policy contains placeholders. Edit them before attaching the policy:

1. **Break-glass role ARN**. `arn:aws:iam::*:role/BreakGlassEKSAdmin` appears in every file. Replace it with the real break-glass role ARN(s) for your organisation. Use a JSON array if you have more than one.
2. **Approved KMS CMK ARN**. `arn:aws:kms:*:111122223333:key/REPLACE-WITH-APPROVED-CMK-UUID` appears in SCP 4 only. Replace it with the ARN(s) of your approved customer-managed KMS CMK(s). Add more ARNs to the array if multiple CMKs are acceptable.
3. **Kubernetes version floor**. SCPs 5 and 6 use `1.31` as the example floor. Bump this to match your organisational minimum before deploying, and re-bump it on every EKS version-lifecycle event.
4. **Control-plane scaling tier**. SCP 10 pins to `STANDARD`. Expand to a JSON array (e.g. `["STANDARD", "ENTERPRISE"]`) if more than one tier is acceptable, and confirm the current valid tier names in the Service Authorization Reference.

## Validating the policies

```bash
# JSON syntax check
for f in scps/*.json; do python3 -c "import json,sys; json.load(open('$f'))" && echo "OK: $f"; done

# AWS-side validation of operators, keys, and SCP semantics
for f in scps/*.json; do
  aws accessanalyzer validate-policy \
    --policy-document file://"$f" \
    --policy-type SERVICE_CONTROL_POLICY
done
```

`accessanalyzer validate-policy` rejects unrecognised condition keys for the named service, so it is the safest way to confirm every `eks:*` key is spelled correctly before you attach the SCP to a real OU.

## Deployment checklist

1. Replace the break-glass role ARN and the KMS CMK ARN placeholders (see "Before you deploy").
2. Run `aws accessanalyzer validate-policy` against every file. Fix any findings before attaching.
3. Attach each policy to a **non-production OU first**. Trigger each denied call from an account inside the OU and confirm you get `AccessDeniedException` with the SCP `Sid` in the message body.
4. Assume the break-glass role and confirm the same call is permitted. This verifies the carve-out actually works before you need it under pressure.
5. Promote to production OUs.
6. Re-read the [Service Authorization Reference for Amazon EKS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelastickubernetesservice.html) periodically so that you pick up new condition keys, new approved values (for example new control-plane scaling tiers), and any deprecated key names.

## Known limitations

- **Cluster-level only.** These ten SCPs cover cluster configuration. They do not govern nodegroup configuration, Fargate profiles, access entries, EKS add-ons, or the Pod Identity service. Those need separate SCPs and IAM policies.
- **Lexicographic version comparison.** SCPs 5 and 6 compare Kubernetes versions with `StringLessThan`, which is lexicographic. This is correct today (`1.28 < 1.29 < 1.30 < 1.31`) because the values are the same width and share the constant `1.` prefix. It will give wrong answers once any minor version reaches three digits: `"1.100"` sorts below `"1.31"`. Re-evaluate the operator (or zero-pad the comparison value) before that day arrives.
- **Break-glass trust assumption.** All ten policies exempt the break-glass principal. If that role is compromised, the SCPs are bypassed. Lock the role down with strong MFA, session tagging, alerting on every assume-role event, and ideally short-lived just-in-time access.
- **Service-linked roles and management account.** SCPs do not apply to service-linked roles or to the org management account. Avoid running production EKS workloads in the management account.

## Sources

The primary source for every key, operator, and applicable API action used here is the AWS announcement [Amazon EKS enhances cluster governance with new IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/) (April 2026). Each SCP section in [`TOP_10_EKS_SCPS.md`](./TOP_10_EKS_SCPS.md) lists the additional AWS doc pages and third-party references used to corroborate the specific risk and the specific SCP shape.
