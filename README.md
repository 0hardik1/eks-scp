# eks-scp

Top 10 highest-impact AWS Organizations Service Control Policies (SCPs) for Amazon EKS, built on the seven new EKS-specific IAM condition keys that AWS released in April 2026.

For the in-depth explanation, risk analysis, working JSON, verification steps, and sources, see [`TOP_10_EKS_SCPS.md`](./TOP_10_EKS_SCPS.md).

## Layout

```
README.md            this file (index)
TOP_10_EKS_SCPS.md   in-depth report: one section per SCP
scps/                deployable SCP JSON files, one per policy
```

## The 10 SCPs

| # | File | Blocks |
|---|---|---|
| 1 | [`scps/01-deny-public-endpoint-at-create.json`](./scps/01-deny-public-endpoint-at-create.json) | Creating a cluster with a public API endpoint |
| 2 | [`scps/02-deny-enabling-public-endpoint-on-update.json`](./scps/02-deny-enabling-public-endpoint-on-update.json) | Flipping an existing cluster's API endpoint to public |
| 3 | [`scps/03-require-private-endpoint.json`](./scps/03-require-private-endpoint.json) | Creating or updating a cluster without the private endpoint enabled |
| 4 | [`scps/04-require-approved-kms-cmk.json`](./scps/04-require-approved-kms-cmk.json) | Creating a cluster without envelope encryption using an approved customer-managed KMS CMK |
| 5 | [`scps/05-enforce-minimum-kubernetes-version-on-create.json`](./scps/05-enforce-minimum-kubernetes-version-on-create.json) | Creating a cluster pinned to a Kubernetes version below the organisational floor |
| 6 | [`scps/06-block-downgrade-or-deprecated-version-on-update.json`](./scps/06-block-downgrade-or-deprecated-version-on-update.json) | Updating an existing cluster to a Kubernetes version below the floor |
| 7 | [`scps/07-require-deletion-protection-on-create.json`](./scps/07-require-deletion-protection-on-create.json) | Creating a cluster without deletion protection |
| 8 | [`scps/08-deny-disabling-deletion-protection.json`](./scps/08-deny-disabling-deletion-protection.json) | Disabling deletion protection on an existing cluster |
| 9 | [`scps/09-require-zonal-shift-enabled.json`](./scps/09-require-zonal-shift-enabled.json) | Creating or updating a cluster with zonal shift disabled |
| 10 | [`scps/10-restrict-control-plane-scaling-tier.json`](./scps/10-restrict-control-plane-scaling-tier.json) | Creating or updating a cluster with a non-approved control-plane scaling tier |

## Before you deploy

Every policy contains two placeholders. Edit them before attaching the policy:

1. `arn:aws:iam::*:role/BreakGlassEKSAdmin` (in every file): replace with the real break-glass role ARN(s) for your organisation. Use a JSON array if you have more than one.
2. `arn:aws:kms:*:111122223333:key/REPLACE-WITH-APPROVED-CMK-UUID` (in SCP 4 only): replace with the ARN(s) of your approved customer-managed KMS CMK(s).

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

## Sources

The primary source for every key, operator, and applicable API action used here is the AWS announcement [Amazon EKS enhances cluster governance with new IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/) (April 2026). Each SCP section in [`TOP_10_EKS_SCPS.md`](./TOP_10_EKS_SCPS.md) lists the additional AWS doc pages and third-party references used to corroborate the specific risk and the specific SCP shape.
