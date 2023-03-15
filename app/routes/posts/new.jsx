import { Link, redirect, useActionData, json } from 'remix'
import { db } from '~/utils/db.server'
import { getUser } from '~/utils/session.server'

function validateTitle(title) {
    if(typeof title !== 'string' || title.length < 3) {
        return 'Title should be at least 3 characters long'
    }
}

function validateBody(body) {
    if(typeof body !== 'string' || body.length < 10) {
        return 'Body should be at least 10 characters long'
    }
}

function badRequest(data) {
    return json(data, {status: 400})
}

// action runs on server
export const action = async ({request}) => {
    const form = await request.formData()
    const title = form.get('title')
    const body = form.get('body')
    const user = await getUser(request)

    const fields = {title: title, body: body}

    const fieldErrors = {
        title: validateTitle(title),
        body: validateBody(body)
    }

    //Object.values will create an array of the values of the object we pass to it
    // if any values exists, then will return true
    if(Object.values(fieldErrors).some(Boolean)) {
        console.log(fieldErrors)
        return badRequest({fieldErrors, fields})
    }

    // making a post without a user associated with it
    //const post = await db.post.create({data: fields})

    // making a post with a user associated with it
    const post = await db.post.create({data: {...fields, userId: user.id}})

    return redirect(`/posts/${post.id}`)
}

function NewPost() {
    const actionData = useActionData();

    return (
        <>
            <div className="page-header">
                <h1>New Post</h1>
                <Link to='/posts' className='btn btn-reverse'>
                    Back
                </Link>
            </div>

            <div className="page-content">
                <form method='POST'>
                    <div className="form-control">
                        <label htmlFor="title">Title</label>
                        <input 
                            type="text" 
                            name='title' 
                            id='title' 
                            defaultValue={actionData?.fields?.title} 
                        />
                        <div className="error">
                            <p>
                                {actionData?.fieldErrors?.title && actionData?.fieldErrors?.title}
                            </p>
                        </div>
                    </div>
                    <div className="form-control">
                        <label htmlFor="body">Post Body</label>
                        <textarea 
                            name='body' 
                            id='body' 
                            defaultValue={actionData?.fields?.body}
                        />
                        <div className="error">
                            <p>
                                {actionData?.fieldErrors?.body && actionData?.fieldErrors?.body}
                            </p>
                        </div>
                    </div>
                    <button type='submit' className="btn btn-block">
                        Add Post
                    </button>
                </form>
            </div>
        </>
    )
}

// could leave this error handling here, but we will put it in the route
// export function ErrorBoundary({error}) {
//     console.log(error)
//     return (
//         <div>
//             <h1>Error</h1>
//             <p>{error.message}</p>
//         </div>
//     )
// }

export default NewPost