from pydantic import BaseModel, Field, conlist
from enum import Enum


class MathOperation(Enum):
    S = 1
    M = 2
    A = 3


class MathProtocol(BaseModel):

    message_id: int = Field(ge=0, le=9999)
    flag: MathOperation
    numbers: conlist(int, min_items=2)

    @classmethod
    def from_string(cls, string: str) -> 'MathProtocol':

        values: list[str] = string.split(";")
        assert(len(values) == 3)

        message_id = int(values[0])
        flag = MathOperation[values[1]]
        numbers = [int(number) for number in values[2].split(" ")]

        return cls(message_id=message_id, flag=flag, numbers=numbers)

    def __str__(self) -> str:

        number_string = ""
        for number in self.numbers:
            number_string = number_string + str(number) + " "

        number_string = number_string[:-1]
        return f"{self.message_id};{self.flag.name};{number_string}"







