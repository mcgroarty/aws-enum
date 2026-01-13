# TODO

## Route53 DNS Audit Feature

**Goal**: Detect dangling DNS records and external/third-party targets that could indicate subdomain takeover risks or shadow IT.

### The Problem

Route53 records can point to:
- **A records** → IP addresses (EC2, ELB, on-prem, third-party)
- **CNAME records** → Domain names (ELB DNS, CloudFront, external services)
- **ALIAS records** → AWS resources (safer - they fail if resource is deleted)

We need to identify:
1. Records pointing to resources outside our AWS accounts
2. Dangling records pointing to deleted AWS resources (subdomain takeover risk)
3. External/third-party services (shadow IT visibility)

### Implementation Phases

#### Phase 1: Show Records with External Detection (Simple, High Value)

Add `--show-records` flag to `route53` command:
- List all DNS records per zone
- Pattern-match CNAME targets against known AWS patterns:
  ```
  *.elb.amazonaws.com         → Load Balancers
  *.elb.*.amazonaws.com       → Regional ELBs  
  *.cloudfront.net            → CloudFront
  *.s3.amazonaws.com          → S3
  *.rds.amazonaws.com         → RDS
  *.cache.amazonaws.com       → ElastiCache
  ```
- Flag any CNAME not matching `*.amazonaws.com` or `*.aws` as 🔶 External

**Output example:**
```
=== Production (123456789012) ===
  Hosted Zones:
    example.com (Z1234) public 42 records
      A     www.example.com          → 52.1.2.3
      CNAME api.example.com          → my-alb-123.us-west-2.elb.amazonaws.com
      CNAME mail.example.com         → mailgun.org                              🔶 External
      CNAME shop.example.com         → shops.myshopify.com                      🔶 External
```

#### Phase 2: Cross-Reference ELBs (Detect Dangling)

Verify AWS resource CNAMEs actually exist:
- We already enumerate ELBs across all accounts
- Build a set of all known ELB DNS names
- For any CNAME → `*.elb.amazonaws.com`, check if ELB exists
- Flag as 🔴 Dangling if not found

**Requires**: Running ELB enumeration first (or caching results)

#### Phase 3: IP Audit

For A records pointing to public IPs:
- Enumerate all Elastic IPs across accounts
- Enumerate all EC2 public IPs
- Cross-reference A record IPs against inventory
- Flag unknown IPs as 🔶 Unknown

**Complexity**: EC2 public IPs can be dynamic; Elastic IPs are more reliable.

### Technical Notes

- Route53 `ListResourceRecordSets` is paginated
- ALIAS records have `AliasTarget` instead of `ResourceRecords`
- Consider rate limiting for large zones
- May want `--external-only` filter to reduce noise

### AWS Patterns Reference

```python
AWS_PATTERNS = [
    r'\.elb\.amazonaws\.com$',
    r'\.elb\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$',
    r'\.cloudfront\.net$',
    r'\.s3\.amazonaws\.com$',
    r'\.s3-[a-z]+-[a-z]+-\d\.amazonaws\.com$',
    r'\.rds\.amazonaws\.com$',
    r'\.cache\.amazonaws\.com$',
    r'\.execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$',  # API Gateway
    r'\.awsglobalaccelerator\.com$',
]
```

### Related Reading

- [Subdomain Takeover on AWS](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html)
- OWASP Subdomain Takeover documentation
