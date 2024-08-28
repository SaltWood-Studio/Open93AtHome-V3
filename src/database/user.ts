import { PrimaryKey, Table } from "../sqlite";

// TypeScript 等效的 UserEntity 类
@Table('users', `
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT NOT NULL, 
    photo TEXT,
    isSuperUser INTEGER DEFAULT 0
`)
@PrimaryKey('id')
export class UserEntity {
    public id: number;
    public username: string;
    public photo: string;
    public isSuperUser: boolean = false;

    constructor(id: number = 0, username: string = '', photo: string = '') {
        this.id = id;
        this.username = username;
        this.photo = photo;
    }
}