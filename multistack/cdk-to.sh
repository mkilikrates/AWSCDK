#!/usr/bin/env bash
if [[ $# -ge 2 ]]; then
    if [ -n "$1" ] && [ "$1" -eq "$1" ] 2>/dev/null; then
        export CDK_DEPLOY_ACCOUNT=$1
        export CDK_DEPLOY_REGION=$2
    else
	ASSUME_ROLE_ARN=$1
	SESSION_NAME=CROSSACCOUNTSESSION
        export CDK_DEPLOY_ACCOUNT=$(echo $1 | cut -d':' -f 5)
        export CDK_DEPLOY_REGION=$2
	creds=$(mktemp -d)/creds.json
	echo "assuming role ${ASSUME_ROLE_ARN} with session-name ${SESSION_NAME}"
        aws sts assume-role --role-arn $ASSUME_ROLE_ARN --role-session-name $SESSION_NAME > $creds
        export AWS_ACCESS_KEY_ID=$(cat ${creds} | grep "AccessKeyId" | cut -d '"' -f 4)
        export AWS_SECRET_ACCESS_KEY=$(cat ${creds} | grep "SecretAccessKey" | cut -d '"' -f 4)
        export AWS_SESSION_TOKEN=$(cat ${creds} | grep "SessionToken" | cut -d '"' -f 4)
    fi
    shift; shift
    cdk "$@"
    exit $?
else
    echo 1>&2 "Provide AWS account or role to account and region as first two args."
    echo 1>&2 "Additional args are passed through to cdk"
    echo 1>&2 "eg: ./cdk-to.sh 1234567890 eu-west-1 diff"
    echo 1>&2 "eg: ./cdk-to.sh arn:aws:iam::22222222222:role/CrossAccountAdmin eu-west-1 deploy --all --require-approval never"
    exit 1
fi
