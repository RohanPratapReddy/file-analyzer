# Locust (.locustfile) analyzer.
#
# Locust load tests are ordinary Python using the `locust` framework; the file
# grammar is Python (AST-parsed by the shared base).  Domain constructs:
#
#     from locust import HttpUser, task, between          -> import
#     class WebsiteUser(HttpUser):                         -> class (virtual user)
#         wait_time = between(1, 5)                         -> class variable
#         @task                                             -> method (weighted task)
#         def index(self): self.client.get("/")
#         @task(3)                                          -> method (weighted task)
#         def about(self): self.client.get("/about")
#     class Flow(SequentialTaskSet): ...                    -> class (task set)
#     @events.test_start.add_listener                       -> function (event hook)
#     def on_start(environment, **kw): ...
#
# Classes subclassing an HttpUser/User/TaskSet type are the domain entry points;
# they are tagged in addition to the full Python pass (@task methods and
# wait_time are captured as methods/variables by the base).
from .python_embedded_base import PythonEmbeddedAnalyzer


class LocustAnalyzer(PythonEmbeddedAnalyzer):
    LANG_KEY = "locust"
    EXTENSIONS = (".locustfile",)
    DSL_BASECLASSES = (
        "HttpUser", "locust.HttpUser", "User", "locust.User",
        "FastHttpUser", "locust.contrib.fasthttp.FastHttpUser",
        "TaskSet", "locust.TaskSet", "SequentialTaskSet",
        "locust.SequentialTaskSet",
    )
    DSL_DECORATORS = ("task", "locust.task", "tag", "locust.tag")
