#!/usr/bin/env python3

from aws_cdk import core

from mytestvpc.mytestvpc_stack import MytestvpcStack


app = core.App()
MytestvpcStack(app, "mytestvpc")

app.synth()
