# White-label overlay for the WAF console image.
#
# Build ONLY under a written authorisation from the image's copyright holder
# that covers modification and redistribution (see docs/LICENSING.vi.md), and
# push the result to a PRIVATE registry.
#
#   docker build --build-arg UPSTREAM=chaitin/safeline-mgt-g:9.2.7 \
#     -t registry.hitechcloud.vn/waf/mgt:9.2.7 branding/console
ARG UPSTREAM=chaitin/safeline-mgt-g:9.2.7
FROM ${UPSTREAM}
COPY brand/ /tmp/brand/
RUN sh /tmp/brand/apply.sh /app/static && rm -rf /tmp/brand
LABEL org.opencontainers.image.title="HiTechCloud WAF Console" \
      org.opencontainers.image.vendor="Pho Tue SoftWare Solutions JSC / HiTechCloud-VN"
