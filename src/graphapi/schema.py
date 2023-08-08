import uuid
from datetime import datetime
import graphene


class Question(graphene.ObjectType):
    id = graphene.ID()
    content = graphene.String()
    answer = graphene.String()
    content = graphene.String()
    ts = graphene.String()

class History(graphene.ObjectType):
    id = graphene.ID()
    questions = graphene.List(Question)  # maybe a dict with Q&A
    ts = graphene.String()

class Query(graphene.ObjectType):
    question = graphene.Field(Question, id=graphene.ID(), content=graphene.String())
    history = graphene.Field(History, id=graphene.ID())
    time_format = '%Y-%m-%d %H:%M:%S'

    def resolve_question(self, info, content, id=None) -> Question:
        if not id:
            # new conversation
            return Question(id=uuid.uuid4(),
                            answer="thanks for the new conversation!",
                            content=content,
                            ts=datetime.utcnow().strftime(Query.time_format))

        else:
            return Question(id=id,
                            answer="What is the meaning of life?",
                            content=content,
                            ts=datetime.utcnow().strftime(Query.time_format))

    def resolve_history(self, info, id) -> History:
        return History(id=id,
                       questions=[Question(id=uuid.uuid4(),
                                           answer="What is the meaning of life?",
                                           ts=datetime.utcnow().strftime(Query.time_format)),
                                  Question(id=uuid.uuid4(),
                                           answer="42",
                                           ts=datetime.utcnow().strftime(Query.time_format))],
                       ts=datetime.utcnow().strftime(Query.time_format))

schema = graphene.Schema(query=Query)
