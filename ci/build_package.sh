#!/bin/bash
set -x
set -e

export TARGET_DIR=/data/RPMS/$CI_PROJECT_NAMESPACE/$CI_COMMIT_REF_NAME/CentOS/7/irods-$IRODS_VERSION
export CONTAINER_NAME=build_${PACKAGE_NAME}_$( echo $IRODS_VERSION | tr '.' '_' )
export IMAGE=$( echo $DOCKER_IMAGE | \
                sed 's/__IRODS_VERSION__/'$( echo $IRODS_VERSION | tr '.' '_' )'/g' )



mkdir -p $TARGET_DIR
set +x
docker rm ${CONTAINER_NAME} || true
set -x

docker run --name ${CONTAINER_NAME} -u rpmbuild -w="/build" -v$( pwd):/build --entrypoint "" ${IMAGE} \
       /opt/irods-externals/cmake3.11.4-0/bin/cmake -DIRODS_$( echo 4.2.8 | tr . _ ) .
       
docker run --name ${CONTAINER_NAME} -u rpmbuild -v$( pwd):/build --entrypoint "" ${IMAGE} \
       /home/rpmbuild/build_rpm.sh \
       --irods-version ${IRODS_VERSION} \
       --spec-file /build/irods_auth_plugin_pam_interactive.spec \
       --package ${PACKAGE_NAME} \
       --version $VERSION \
       --release ${CI_PIPELINE_ID}
docker cp ${CONTAINER_NAME}:/home/rpmbuild/rpmbuild/RPMS/x86_64 $TARGET_DIR
docker rm ${CONTAINER_NAME}
