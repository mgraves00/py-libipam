#
COMMENT =		python interface to manipulate a simple IPAM database

V =			1.0.12
MODPY_EGG_VERSION =	${V}
#REVISION =		0
DISTNAME =		py-libipam-${V}

CATEGORIES =		net

HOMEPATH =		https://github.com/mgraves00/py-libipam/

MAINTAINER =		Michael Graves

SITES = 		https://github.com/mgraves00/py-libipam/releases/download/v${V}/

# BSD 3 clause
PERMIT_PACKAGE =	Yes
PERMIT_DISTFILES =	Yes

MODULES =		lang/python

MODPY_PI =		No
MODPY_PYBUILD = 	setuptools

NO_TEST =		Yes

RUN_DEPENDS =		www/py-requests${MODPY_FLAVOR}
FLAVORS =		python3
FLAVOR =		python3


.include <bsd.port.mk>
