# AWS CDK application (.cdk).
#
# A CDK app is ordinary TypeScript: it imports constructs from `aws-cdk-lib`,
# declares `Stack` / `Construct` subclasses, and synthesises resources with
# `new <Resource>(this, "id", {props})`.  The syntax is TypeScript, so the
# honest analyzer is the tree-sitter TS engine with the `.cdk` extension:
#
#     import * as cdk from "aws-cdk-lib";              -> import
#     import { Bucket } from "aws-cdk-lib/aws-s3";     -> import
#     export class MyStack extends cdk.Stack {         -> class (extends Stack)
#       constructor(scope: Construct, id: string) {    -> method
#         super(scope, id);
#         new Bucket(this, "Data", { versioned: true });
#       }
#     }
#     const app = new cdk.App();                       -> variable
#
# Every import / class / interface / type / function / variable a real CDK app
# contains is captured by the inherited TypeScript extraction unchanged.
from .javascript_analyzer import TypeScriptAnalyzer


class CdkAnalyzer(TypeScriptAnalyzer):
    def __init__(self, **kwargs):
        # grammar stays the TypeScript tree-sitter parser; only the recorded
        # language name and on-disk extension change.
        super().__init__(**kwargs)
        self.extensions = [".cdk"]
        self.language_name = "cdk"
        self.introspection_source = (
            "AWS CDK app (TypeScript: Stack/Construct subclasses, "
            "new <Resource>(scope, id, props) synthesis)"
        )
