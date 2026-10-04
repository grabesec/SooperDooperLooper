# A small OpenLDAP directory for the SDL lab, with its people and groups baked in.
FROM ubuntu:24.04
RUN echo 'slapd slapd/no_configuration boolean true' | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY config.ldif directory.ldif /lab/
RUN rm -rf /etc/ldap/slapd.d /var/lib/ldap \
 && mkdir -p /etc/ldap/slapd.d /var/lib/ldap \
 && slapadd -n0 -F /etc/ldap/slapd.d -l /lab/config.ldif \
 && slapadd -n1 -F /etc/ldap/slapd.d -l /lab/directory.ldif \
 && chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap \
 && mkdir -p /run/slapd && chown openldap:openldap /run/slapd
EXPOSE 389
# -d stats logs every bind and search, so sign-ins can be followed with ./lab/lab.sh logs ldap.
CMD ["slapd", "-h", "ldap:///", "-u", "openldap", "-g", "openldap", "-F", "/etc/ldap/slapd.d", "-d", "stats"]
