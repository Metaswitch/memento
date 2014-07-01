# included mk file for memento

CEDAR_DIR := ${ROOT}/src
CEDAR_TEST_DIR := ${ROOT}/tests

memento:
	make -C ${CEDAR_DIR}

memento_test:
	make -C ${CEDAR_DIR} test

memento_clean:
	make -C ${CEDAR_DIR} clean

memento_distclean: memento_clean

.PHONY: memento memento_test memento_clean memento_distclean
